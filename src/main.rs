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
    #[serde(default = "default_path_keys")]
    path_keys: Vec<String>,
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self {
            blocked_patterns: default_blocked_patterns(),
            allowed_patterns: default_allowed_patterns(),
            block_path_traversal: true,
            path_keys: default_path_keys(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
struct CommandsConfig {
    #[serde(default = "default_blocked_commands")]
    blocked_commands: Vec<String>,
    #[serde(default = "default_true")]
    check_all_tools: bool,
    #[serde(default = "default_shell_tools")]
    shell_tools: Vec<String>,
}

impl Default for CommandsConfig {
    fn default() -> Self {
        Self {
            blocked_commands: default_blocked_commands(),
            check_all_tools: true,
            shell_tools: default_shell_tools(),
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
fn default_path_keys() -> Vec<String> {
    vec![
        "path".into(),
        "uri".into(),
        "paths".into(),
        "source".into(),
        "destination".into(),
        "src".into(),
        "dest".into(),
        "target".into(),
        "from".into(),
        "to".into(),
        "file".into(),
        "filename".into(),
        "directory".into(),
        "dir".into(),
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
fn default_shell_tools() -> Vec<String> {
    vec![
        "execute_command".into(),
        "bash".into(),
        "sh".into(),
        "shell".into(),
        "run_shell".into(),
        "run_command".into(),
        "terminal".into(),
        "exec".into(),
        "powershell".into(),
        "cmd".into(),
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

    fn find_blocked_pattern(&self, text: &str) -> Option<&str> {
        let filesystem = &self.config.filesystem;
        let mut remaining = text.to_string();
        for allowed in filesystem.allowed_patterns.iter().filter(|a| !a.is_empty()) {
            remaining = remaining.replace(allowed.as_str(), "\0");
        }
        filesystem
            .blocked_patterns
            .iter()
            .map(String::as_str)
            .find(|pattern| remaining.contains(pattern))
    }

    fn check_path(&self, path_val: &str) -> Option<String> {
        if self.config.filesystem.block_path_traversal
            && (path_val.contains("../") || path_val.contains("..\\"))
        {
            return Some("Explicit path traversal ('../') attempt detected".into());
        }

        let candidate = PathBuf::from(path_val);

        let Some(can_candidate) = resolve_path(&candidate) else {
            return Some(format!("Could not resolve target path: {path_val}"));
        };
        let cand_str = can_candidate.to_string_lossy();
        let clean_candidate = cand_str.strip_prefix(r"\\?\").unwrap_or(&cand_str);

        if self.config.filesystem.block_path_traversal {
            let Ok(can_root) = self.workspace_root.canonicalize() else {
                return Some("Could not resolve workspace root".into());
            };
            let root_str = can_root.to_string_lossy();
            let clean_root = root_str.strip_prefix(r"\\?\").unwrap_or(&root_str);

            if !clean_candidate.starts_with(clean_root) {
                return Some(format!(
                    "Resolved target path escapes workspace boundary: {clean_candidate}"
                ));
            }
        }

        if let Some(pattern) = self.find_blocked_pattern(clean_candidate) {
            return Some(format!(
                "Resolved target matches prohibited pattern '{pattern}'"
            ));
        }

        None
    }

    fn inspect_tool_call(&self, tool_name: &str, args: &Option<Value>) -> PolicyDecision {
        let args_str = match args {
            Some(v) => v.to_string(),
            None => String::new(),
        };

        if let Some(Value::Object(map)) = args {
            for key in &self.config.filesystem.path_keys {
                let path_vals: Vec<&str> = match map.get(key) {
                    Some(Value::String(s)) => vec![s.as_str()],
                    Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
                    _ => continue,
                };
                for path_val in path_vals {
                    if let Some(reason) = self.check_path(path_val) {
                        return PolicyDecision::Block(reason);
                    }
                }
            }
        }

        if let Some(pattern) = self.find_blocked_pattern(&args_str) {
            return PolicyDecision::Block(format!(
                "Argument payload contains prohibited pattern '{pattern}'"
            ));
        }

        let commands = &self.config.commands;
        if commands.check_all_tools || commands.shell_tools.iter().any(|t| t == tool_name) {
            for cmd in &commands.blocked_commands {
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

    fn check_args(workspace: &Path, tool: &str, args: Value) -> bool {
        let engine = SecurityEngine::new(AppConfig::default(), workspace.to_path_buf());
        matches!(
            engine.inspect_tool_call(tool, &Some(args)),
            PolicyDecision::Block(_)
        )
    }

    fn check_with_config(config_toml: &str, workspace: &Path, tool: &str, args: Value) -> bool {
        let config: AppConfig = toml::from_str(config_toml).unwrap();
        let engine = SecurityEngine::new(config, workspace.to_path_buf());
        matches!(
            engine.inspect_tool_call(tool, &Some(args)),
            PolicyDecision::Block(_)
        )
    }

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

    #[test]
    fn blocks_new_file_outside_workspace() {
        let (ws, outside) = setup("case1");
        let target = outside.join("evil.ps1");
        assert!(
            check(&ws, "write_file", &target),
            "new file outside workspace was allowed"
        );
    }

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

    #[test]
    fn allows_new_file_in_workspace() {
        let (ws, _) = setup("case3");
        let target = ws.join("notes.txt");
        assert!(
            !check(&ws, "write_file", &target),
            "new file in workspace was blocked"
        );
    }

    #[test]
    fn allows_new_file_in_new_subfolder() {
        let (ws, _) = setup("case4");
        let target = ws.join("src").join("new").join("lib.rs");
        assert!(
            !check(&ws, "write_file", &target),
            "new file in new subfolder was blocked"
        );
    }

    #[test]
    fn blocks_new_env_file_in_workspace() {
        let (ws, _) = setup("case5");
        let target = ws.join(".env");
        assert!(
            check(&ws, "write_file", &target),
            "new .env file was allowed"
        );
    }

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

    #[test]
    fn blocks_key_inside_folder_named_like_allowed_pattern() {
        let (ws, _) = setup("case1a");
        let target = ws.join(".env.example-old").join("id_rsa");
        assert!(
            check(&ws, "write_file", &target),
            "id_rsa inside '.env.example-old' folder was allowed"
        );
    }

    #[test]
    fn blocks_ssh_inside_folder_named_like_allowed_pattern() {
        let (ws, _) = setup("case1b");
        let target = ws.join(".env.sample").join(".ssh").join("authorized_keys");
        assert!(
            check(&ws, "write_file", &target),
            ".ssh inside '.env.sample' folder was allowed"
        );
    }

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

    #[test]
    fn allows_env_example_file() {
        let (ws, _) = setup("case1d");
        let target = ws.join(".env.example");
        assert!(
            !check(&ws, "write_file", &target),
            ".env.example was blocked"
        );
    }

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

    #[test]
    fn blocks_destructive_command_in_run_shell() {
        let (ws, _) = setup("case2a");
        let args = json!({ "command": "rm -rf ~" });
        assert!(
            check_args(&ws, "run_shell", args),
            "rm -rf through run_shell was allowed"
        );
    }

    #[test]
    fn blocks_destructive_command_in_terminal() {
        let (ws, _) = setup("case2b");
        let args = json!({ "cmd": "mkfs.ext4 /dev/sda" });
        assert!(
            check_args(&ws, "terminal", args),
            "mkfs through terminal was allowed"
        );
    }

    #[test]
    fn blocks_destructive_command_in_any_tool_by_default() {
        let (ws, _) = setup("case2c");
        let args = json!({
            "path": ws.join("run.sh").to_string_lossy(),
            "content": "rm -rf /",
        });
        assert!(
            check_args(&ws, "write_file", args),
            "write_file containing rm -rf was allowed"
        );
    }

    #[test]
    fn blocks_destructive_command_in_bash() {
        let (ws, _) = setup("case2d");
        let args = json!({ "command": "rm -rf /" });
        assert!(
            check_args(&ws, "bash", args),
            "rm -rf through bash was allowed"
        );
    }

    #[test]
    fn allows_harmless_command_in_run_shell() {
        let (ws, _) = setup("case2e");
        let args = json!({ "command": "ls -la" });
        assert!(
            !check_args(&ws, "run_shell", args),
            "ls -la through run_shell was blocked"
        );
    }

    #[test]
    fn blocks_listed_shell_tool_when_check_all_tools_off() {
        let (ws, _) = setup("case2f");
        let config = r#"
            [commands]
            check_all_tools = false
            shell_tools = ["run_shell"]
        "#;
        let args = json!({ "command": "rm -rf ~" });
        assert!(
            check_with_config(config, &ws, "run_shell", args),
            "rm -rf through listed run_shell was allowed"
        );
    }

    #[test]
    fn allows_unlisted_tool_when_check_all_tools_off() {
        let (ws, _) = setup("case2g");
        let config = r#"
            [commands]
            check_all_tools = false
        "#;
        let args = json!({
            "path": ws.join("run.sh").to_string_lossy(),
            "content": "rm -rf /",
        });
        assert!(
            !check_with_config(config, &ws, "write_file", args),
            "write_file was command-checked with check_all_tools off"
        );
    }

    #[test]
    fn blocks_move_file_source_outside_workspace() {
        let (ws, outside) = setup("case3a");
        let args = json!({
            "source": outside.join("secret.txt").to_string_lossy(),
            "destination": ws.join("secret.txt").to_string_lossy(),
        });
        assert!(
            check_args(&ws, "move_file", args),
            "move_file with source outside workspace was allowed"
        );
    }

    #[test]
    fn blocks_move_file_destination_outside_workspace() {
        let (ws, outside) = setup("case3b");
        let args = json!({
            "source": ws.join("notes.txt").to_string_lossy(),
            "destination": outside.join("notes.txt").to_string_lossy(),
        });
        assert!(
            check_args(&ws, "move_file", args),
            "move_file with destination outside workspace was allowed"
        );
    }

    #[test]
    fn blocks_copy_file_destination_through_link() {
        let (ws, outside) = setup("case3c");
        let link = ws.join("out");
        link_dir(&outside, &link);
        let args = json!({
            "source": ws.join("notes.txt").to_string_lossy(),
            "destination": link.join("notes.txt").to_string_lossy(),
        });
        assert!(
            check_args(&ws, "copy_file", args),
            "copy_file through link to outside was allowed"
        );
    }

    #[test]
    fn blocks_read_multiple_files_with_one_outside() {
        let (ws, outside) = setup("case3d");
        let args = json!({
            "paths": [
                ws.join("a.txt").to_string_lossy(),
                outside.join("b.txt").to_string_lossy(),
            ],
        });
        assert!(
            check_args(&ws, "read_multiple_files", args),
            "read_multiple_files with an outside path was allowed"
        );
    }

    #[test]
    fn blocks_outside_uri_next_to_inside_path() {
        let (ws, outside) = setup("case3e");
        let args = json!({
            "path": ws.join("a.txt").to_string_lossy(),
            "uri": outside.join("b.txt").to_string_lossy(),
        });
        assert!(
            check_args(&ws, "read_file", args),
            "outside uri next to inside path was allowed"
        );
    }

    #[test]
    fn blocks_traversal_in_destination() {
        let (ws, _) = setup("case3f");
        let args = json!({
            "source": ws.join("notes.txt").to_string_lossy(),
            "destination": "../outside/notes.txt",
        });
        assert!(
            check_args(&ws, "move_file", args),
            "traversal in destination was allowed"
        );
    }

    #[test]
    fn blocks_custom_path_key_from_config() {
        let (ws, outside) = setup("case3g");
        let config = r#"
            [filesystem]
            path_keys = ["dst"]
        "#;
        let args = json!({ "dst": outside.join("notes.txt").to_string_lossy() });
        assert!(
            check_with_config(config, &ws, "custom_copy", args),
            "outside path under custom key 'dst' was allowed"
        );
    }

    #[test]
    fn allows_move_file_within_workspace() {
        let (ws, _) = setup("case3h");
        let args = json!({
            "source": ws.join("a.txt").to_string_lossy(),
            "destination": ws.join("sub").join("a.txt").to_string_lossy(),
        });
        assert!(
            !check_args(&ws, "move_file", args),
            "move_file within workspace was blocked"
        );
    }

    #[test]
    fn allows_read_multiple_files_inside() {
        let (ws, _) = setup("case3i");
        let args = json!({
            "paths": [
                ws.join("a.txt").to_string_lossy(),
                ws.join("b.txt").to_string_lossy(),
            ],
        });
        assert!(
            !check_args(&ws, "read_multiple_files", args),
            "read_multiple_files inside workspace was blocked"
        );
    }
}
