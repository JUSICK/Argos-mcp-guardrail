use chrono::Utc;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use tokio::fs::OpenOptions;
use tokio::io::{self, AsyncWriteExt};
use tokio::process::Command;
use tokio_util::codec::{FramedRead, LinesCodec};

#[derive(Debug, Deserialize, Clone, Default)]
struct AppConfig {
    #[serde(default)]
    filesystem: FilesystemConfig,
    #[serde(default)]
    commands: CommandsConfig,
    #[serde(default)]
    audit: AuditConfig,
}

#[derive(Debug, Deserialize, Clone)]
struct FilesystemConfig {
    #[serde(default = "default_blocked_patterns")]
    blocked_patterns: Vec<String>,
    #[serde(default = "default_allowed_patterns")]
    allowed_patterns: Vec<String>,
    #[serde(default = "default_true")]
    block_path_traversal: bool,
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self {
            blocked_patterns: default_blocked_patterns(),
            allowed_patterns: default_allowed_patterns(),
            block_path_traversal: true,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
struct CommandsConfig {
    #[serde(default = "default_blocked_commands")]
    blocked_commands: Vec<String>,
}

impl Default for CommandsConfig {
    fn default() -> Self {
        Self {
            blocked_commands: default_blocked_commands(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
struct AuditConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_log_file")]
    log_file: String,
    #[serde(default = "default_false")]
    log_allowed: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_file: default_log_file(),
            log_allowed: false,
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}
fn default_log_file() -> String {
    "argos-audit.log".to_string()
}
fn default_blocked_patterns() -> Vec<String> {
    vec![
        ".env".into(),
        ".ssh".into(),
        "id_rsa".into(),
        "id_ed25519".into(),
        "credentials".into(),
        ".npmrc".into(),
        ".aws".into(),
        ".git-credentials".into(),
    ]
}
fn default_allowed_patterns() -> Vec<String> {
    vec![
        ".env.example".into(),
        ".env.sample".into(),
        ".env.template".into(),
    ]
}
fn default_blocked_commands() -> Vec<String> {
    vec![
        "rm -rf".into(),
        "mkfs".into(),
        ":(){ :|:& };:".into(),
        "dd if=".into(),
        "chmod -R 777".into(),
    ]
}

impl AppConfig {
    fn load() -> Self {
        let base_dir = env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));

        let config_path = base_dir.join("argos.toml");
        if config_path.exists() {
            if let Ok(content) = fs::read_to_string(config_path) {
                if let Ok(cfg) = toml::from_str::<AppConfig>(&content) {
                    return cfg;
                }
            }
        }
        AppConfig::default()
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

#[derive(Debug, Serialize)]
struct McpContent {
    #[serde(rename = "type")]
    content_type: &'static str,
    text: String,
}

#[derive(Debug, Serialize)]
struct McpToolResult {
    content: Vec<McpContent>,
    #[serde(rename = "isError")]
    is_error: bool,
}

#[derive(Debug, Serialize)]
struct JsonRpcSuccessResponse {
    jsonrpc: &'static str,
    id: Option<Value>,
    result: McpToolResult,
}

impl JsonRpcSuccessResponse {
    fn blocked(id: Option<Value>, reason: &str) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: McpToolResult {
                content: vec![McpContent {
                    content_type: "text",
                    text: format!(
                        "[SECURITY POLICY VIOLATION] Action rejected by Argos Gateway: {reason}"
                    ),
                }],
                is_error: true,
            },
        }
    }
}

#[derive(Debug, Serialize)]
struct AuditEvent {
    timestamp: String,
    event_type: &'static str,
    tool_name: String,
    reason: Option<String>,
    arguments: Option<Value>,
}

enum PolicyDecision {
    Allow,
    Block(String),
}

// Work out where `raw` really points, even if the file doesn't exist yet.
// `canonicalize()` only works on paths that exist, so walk up to the nearest
// existing folder, canonicalize that (resolving symlinks/junctions), then put
// the not-yet-existing names back on. Returns None if that's not possible,
// e.g. a `..` in the missing part, and the caller then blocks.
fn resolve_path(raw: &Path) -> Option<PathBuf> {
    let absolute = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        env::current_dir().ok()?.join(raw)
    };
    let mut existing = absolute.as_path();
    let mut missing = Vec::new();
    loop {
        if let Ok(real) = existing.canonicalize() {
            let mut resolved = real;
            for name in missing.iter().rev() {
                resolved.push(name);
            }
            return Some(resolved);
        }
        match existing.components().next_back()? {
            Component::Normal(name) => missing.push(name),
            _ => return None,
        }
        existing = existing.parent()?;
    }
}

struct SecurityEngine {
    config: AppConfig,
    workspace_root: PathBuf,
}

impl SecurityEngine {
    fn new(config: AppConfig, workspace_root: PathBuf) -> Self {
        Self {
            config,
            workspace_root,
        }
    }

    // Returns the first blocked pattern found in `text`. Allow-listed names
    // (e.g. `.env.example`) are blanked out first, so they only exempt
    // themselves: an `id_rsa` or `.ssh` elsewhere in the text still counts.
    // They're replaced with `\0` rather than removed, so the pieces on either
    // side can't join up into a new match.
    fn find_blocked_pattern(&self, text: &str) -> Option<&str> {
        let filesystem = &self.config.filesystem;
        let mut remaining = text.to_string();
        // An empty allowed pattern would "match" between every character and
        // scramble the text, so it's skipped.
        for allowed in filesystem.allowed_patterns.iter().filter(|a| !a.is_empty()) {
            remaining = remaining.replace(allowed.as_str(), "\0");
        }
        filesystem
            .blocked_patterns
            .iter()
            .map(String::as_str)
            .find(|pattern| remaining.contains(pattern))
    }

    fn inspect_tool_call(&self, tool_name: &str, args: &Option<Value>) -> PolicyDecision {
        let args_str = match args {
            Some(v) => v.to_string(),
            None => String::new(),
        };

        if let Some(Value::Object(map)) = args {
            let target_path_str = map
                .get("path")
                .or_else(|| map.get("uri"))
                .and_then(|v| v.as_str());

            if let Some(path_val) = target_path_str {
                if self.config.filesystem.block_path_traversal
                    && (path_val.contains("../") || path_val.contains("..\\"))
                {
                    return PolicyDecision::Block(
                        "Explicit path traversal ('../') attempt detected".into(),
                    );
                }

                let candidate = PathBuf::from(path_val);

                // Fail closed: if we can't work out where the path really points,
                // we can't check it, so it doesn't go through.
                let Some(can_candidate) = resolve_path(&candidate) else {
                    return PolicyDecision::Block(format!(
                        "Could not resolve target path: {path_val}"
                    ));
                };
                let cand_str = can_candidate.to_string_lossy();
                let clean_candidate = cand_str.strip_prefix(r"\\?\").unwrap_or(&cand_str);

                if self.config.filesystem.block_path_traversal {
                    let Ok(can_root) = self.workspace_root.canonicalize() else {
                        return PolicyDecision::Block("Could not resolve workspace root".into());
                    };
                    let root_str = can_root.to_string_lossy();
                    let clean_root = root_str.strip_prefix(r"\\?\").unwrap_or(&root_str);

                    if !clean_candidate.starts_with(clean_root) {
                        return PolicyDecision::Block(format!(
                            "Resolved target path escapes workspace boundary: {clean_candidate}"
                        ));
                    }
                }

                if let Some(pattern) = self.find_blocked_pattern(clean_candidate) {
                    return PolicyDecision::Block(format!(
                        "Resolved target matches prohibited pattern '{pattern}'"
                    ));
                }
            }
        }

        if let Some(pattern) = self.find_blocked_pattern(&args_str) {
            return PolicyDecision::Block(format!(
                "Argument payload contains prohibited pattern '{pattern}'"
            ));
        }

        if tool_name == "execute_command" || tool_name == "bash" || tool_name == "sh" {
            for cmd in &self.config.commands.blocked_commands {
                if args_str.contains(cmd) {
                    return PolicyDecision::Block(format!(
                        "Forbidden command sequence '{cmd}' detected"
                    ));
                }
            }
        }

        PolicyDecision::Allow
    }

    async fn log_event(&self, event: AuditEvent) {
        if !self.config.audit.enabled {
            return;
        }

        let base_dir = env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));

        let log_path = if Path::new(&self.config.audit.log_file).is_absolute() {
            PathBuf::from(&self.config.audit.log_file)
        } else {
            base_dir.join(&self.config.audit.log_file)
        };

        if let Ok(serialized) = serde_json::to_string(&event) {
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .await
            {
                let _ = file.write_all(format!("{serialized}\n").as_bytes()).await;
            }
        }
    }
}

fn resolve_program(program: &str) -> String {
    if !cfg!(windows) {
        return program.to_string();
    }
    let path_var = match env::var_os("PATH") {
        Some(p) => p,
        None => return program.to_string(),
    };
    let exts = env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
    let exts: Vec<&str> = exts.split(';').filter(|e| !e.is_empty()).collect();
    for dir in env::split_paths(&path_var) {
        let exact = dir.join(program);
        if exact.is_file() {
            return exact.to_string_lossy().into_owned();
        }
        for ext in &exts {
            let candidate = dir.join(format!("{program}{ext}"));
            if candidate.is_file() {
                return candidate.to_string_lossy().into_owned();
            }
        }
    }
    program.to_string()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw_args: Vec<String> = env::args().collect();
    let separator_pos = raw_args.iter().position(|r| r == "--");

    let target_args = match separator_pos {
        Some(pos) if pos + 1 < raw_args.len() => &raw_args[pos + 1..],
        _ => {
            eprintln!("Usage: argos -- <command> [args...]");
            eprintln!(
                "Example: argos -- npx -y @modelcontextprotocol/server-filesystem /workspace"
            );
            std::process::exit(1);
        }
    };

    let program = &target_args[0];
    let cmd_args = &target_args[1..];

    let config = AppConfig::load();

    let target_workspace = target_args
        .iter()
        .rev()
        .find(|arg| Path::new(arg).is_dir())
        .map(PathBuf::from)
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let engine = SecurityEngine::new(config, target_workspace);

    let mut cmd = Command::new(resolve_program(program));
    cmd.args(cmd_args);

    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("Failed to spawn target process '{program}': {e}"))?;

    let mut child_stdin = child.stdin.take().expect("Failed to open child stdin");
    let child_stdout = child.stdout.take().expect("Failed to open child stdout");

    let stdin_reader = FramedRead::new(io::stdin(), LinesCodec::new());
    let mut stdout_reader = FramedRead::new(child_stdout, LinesCodec::new());
    let mut parent_stdout = io::stdout();

    let stdout_forwarder = tokio::spawn(async move {
        while let Some(Ok(line)) = stdout_reader.next().await {
            let _ = parent_stdout.write_all(line.as_bytes()).await;
            let _ = parent_stdout.write_all(b"\n").await;
            let _ = parent_stdout.flush().await;
        }
    });

    let mut stdin_stream = stdin_reader;

    tokio::select! {
        _ = async {
            while let Some(Ok(line)) = stdin_stream.next().await {
                if let Ok(rpc) = serde_json::from_str::<JsonRpcRequest>(&line) {
                    if rpc.method == "tools/call" {
                        let tool_name = rpc.params.as_ref()
                            .and_then(|p| p.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or_default()
                            .to_string();

                        let args = rpc.params.as_ref().and_then(|p| p.get("arguments")).cloned();

                        match engine.inspect_tool_call(&tool_name, &args) {
                            PolicyDecision::Block(reason) => {
                                engine.log_event(AuditEvent {
                                    timestamp: Utc::now().to_rfc3339(),
                                    event_type: "BLOCKED",
                                    tool_name,
                                    reason: Some(reason.clone()),
                                    arguments: args,
                                }).await;

                                let blocked_reply = JsonRpcSuccessResponse::blocked(rpc.id, &reason);
                                let json_bytes = serde_json::to_vec(&blocked_reply).unwrap();
                                let mut out = io::stdout();
                                let _ = out.write_all(&json_bytes).await;
                                let _ = out.write_all(b"\n").await;
                                let _ = out.flush().await;
                                continue;
                            }
                            PolicyDecision::Allow => {
                                if engine.config.audit.log_allowed {
                                    engine.log_event(AuditEvent {
                                        timestamp: Utc::now().to_rfc3339(),
                                        event_type: "ALLOWED",
                                        tool_name,
                                        reason: None,
                                        arguments: args,
                                    }).await;
                                }
                            }
                        }
                    }
                }

                let _ = child_stdin.write_all(line.as_bytes()).await;
                let _ = child_stdin.write_all(b"\n").await;
                let _ = child_stdin.flush().await;
            }
        } => {}

        _ = tokio::signal::ctrl_c() => {
            eprintln!("\n[argos] Interrupted. Shutting down gracefully...");
        }
    }

    stdout_forwarder.abort();
    let _ = child.kill().await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Each test gets its own fresh folder under the system temp dir:
    //   <temp>/argos-test-<name>/workspace   <- what Argos protects
    //   <temp>/argos-test-<name>/outside     <- somewhere the agent must not reach
    fn setup(name: &str) -> (PathBuf, PathBuf) {
        let base = env::temp_dir().join(format!("argos-test-{name}"));
        let _ = fs::remove_dir_all(&base);
        let workspace = base.join("workspace");
        let outside = base.join("outside");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&outside).unwrap();
        (workspace, outside)
    }

    fn check(workspace: &Path, tool: &str, path: &Path) -> bool {
        let engine = SecurityEngine::new(AppConfig::default(), workspace.to_path_buf());
        let args = Some(json!({ "path": path.to_string_lossy(), "content": "x" }));
        matches!(
            engine.inspect_tool_call(tool, &args),
            PolicyDecision::Block(_)
        )
    }

    // Like `check`, but with any tool name and any arguments (e.g. move_file,
    // which uses `source`/`destination` instead of `path`).
    fn check_args(workspace: &Path, tool: &str, args: Value) -> bool {
        let engine = SecurityEngine::new(AppConfig::default(), workspace.to_path_buf());
        matches!(
            engine.inspect_tool_call(tool, &Some(args)),
            PolicyDecision::Block(_)
        )
    }

    // Makes `link` point at the existing folder `target`. On Windows this is a
    // junction, which (unlike a symlink) needs no admin rights or Developer Mode.
    fn link_dir(target: &Path, link: &Path) {
        #[cfg(windows)]
        {
            let status = std::process::Command::new("cmd")
                .args(["/c", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .stdout(Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "failed to create junction");
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    // Case 1: new file outside the workspace, given as a full path.
    #[test]
    fn blocks_new_file_outside_workspace() {
        let (ws, outside) = setup("case1");
        let target = outside.join("evil.ps1");
        assert!(
            check(&ws, "write_file", &target),
            "new file outside workspace was allowed"
        );
    }

    // Case 2: new file written through a link inside the workspace that
    // points at a sensitive folder outside it.
    #[test]
    fn blocks_new_file_through_link_to_sensitive_dir() {
        let (ws, outside) = setup("case2");
        let ssh = outside.join(".ssh");
        fs::create_dir_all(&ssh).unwrap();
        let link = ws.join("keys");
        link_dir(&ssh, &link);
        let target = link.join("authorized_keys");
        assert!(
            check(&ws, "write_file", &target),
            "new file through link to .ssh was allowed"
        );
    }

    // Case 3: new file directly inside the workspace.
    #[test]
    fn allows_new_file_in_workspace() {
        let (ws, _) = setup("case3");
        let target = ws.join("notes.txt");
        assert!(
            !check(&ws, "write_file", &target),
            "new file in workspace was blocked"
        );
    }

    // Case 4: new file in a subfolder that doesn't exist yet, inside the workspace.
    #[test]
    fn allows_new_file_in_new_subfolder() {
        let (ws, _) = setup("case4");
        let target = ws.join("src").join("new").join("lib.rs");
        assert!(
            !check(&ws, "write_file", &target),
            "new file in new subfolder was blocked"
        );
    }

    // Case 5: new .env file inside the workspace.
    #[test]
    fn blocks_new_env_file_in_workspace() {
        let (ws, _) = setup("case5");
        let target = ws.join(".env");
        assert!(
            check(&ws, "write_file", &target),
            "new .env file was allowed"
        );
    }

    // Case 6: reading an existing ordinary file inside the workspace.
    #[test]
    fn allows_reading_existing_file() {
        let (ws, _) = setup("case6");
        let target = ws.join("readme.txt");
        fs::write(&target, "hello").unwrap();
        assert!(
            !check(&ws, "read_file", &target),
            "reading existing file was blocked"
        );
    }

    // Case 1a: a folder whose name merely contains `.env.example` must not
    // switch off the `id_rsa` check for files inside it.
    #[test]
    fn blocks_key_inside_folder_named_like_allowed_pattern() {
        let (ws, _) = setup("case1a");
        let target = ws.join(".env.example-old").join("id_rsa");
        assert!(
            check(&ws, "write_file", &target),
            "id_rsa inside '.env.example-old' folder was allowed"
        );
    }

    // Case 1b: same trick with `.env.sample` hiding a `.ssh` folder.
    #[test]
    fn blocks_ssh_inside_folder_named_like_allowed_pattern() {
        let (ws, _) = setup("case1b");
        let target = ws.join(".env.sample").join(".ssh").join("authorized_keys");
        assert!(
            check(&ws, "write_file", &target),
            ".ssh inside '.env.sample' folder was allowed"
        );
    }

    // Case 1c: moving a private key onto an allow-listed name. move_file has
    // no `path` key, so only the argument-payload check stands in the way.
    #[test]
    fn blocks_moving_key_to_allowed_name() {
        let (ws, _) = setup("case1c");
        let source = ws.join(".ssh").join("id_rsa");
        let destination = ws.join(".env.example");
        let args = json!({
            "source": source.to_string_lossy(),
            "destination": destination.to_string_lossy(),
        });
        assert!(
            check_args(&ws, "move_file", args),
            "moving id_rsa to .env.example was allowed"
        );
    }

    // Case 1d: the allow-list still does its real job.
    #[test]
    fn allows_env_example_file() {
        let (ws, _) = setup("case1d");
        let target = ws.join(".env.example");
        assert!(
            !check(&ws, "write_file", &target),
            ".env.example was blocked"
        );
    }

    // Case 1e: an ordinary file whose text mentions `.env.example`.
    #[test]
    fn allows_ordinary_file_mentioning_env_example() {
        let (ws, _) = setup("case1e");
        let args = json!({
            "path": ws.join("notes.txt").to_string_lossy(),
            "content": "Copy .env.example before running.",
        });
        assert!(
            !check_args(&ws, "write_file", args),
            "notes.txt mentioning .env.example was blocked"
        );
    }
}
