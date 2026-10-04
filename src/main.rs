use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use chrono::Utc;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::fs::OpenOptions;
use tokio::io::{self, AsyncWriteExt};
use tokio::process::Command;
use tokio_util::codec::{FramedRead, LinesCodec};

#[derive(Debug, Deserialize, Clone)]
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
    #[serde(default = "default_true")]
    block_path_traversal: bool,
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self {
            blocked_patterns: default_blocked_patterns(),
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
    log_allowed: bool, // Додано поле, через яке виникала E0609
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

fn default_true() -> bool { true }
fn default_false() -> bool { false }
fn default_log_file() -> String { "mcp-guard-audit.log".to_string() }
fn default_blocked_patterns() -> Vec<String> {
    vec![
        ".env".into(),
        ".ssh".into(),
        "id_rsa".into(),
        "id_ed25519".into(),
        "credentials".into(),
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

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            filesystem: FilesystemConfig::default(),
            commands: CommandsConfig::default(),
            audit: AuditConfig::default(),
        }
    }
}

impl AppConfig {
    fn load() -> Self {
        let config_path = Path::new("mcp-guard.toml");
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
struct JsonRpcErrorResponse {
    jsonrpc: &'static str,
    id: Option<Value>,
    error: JsonRpcErrorObject,
}

#[derive(Debug, Serialize)]
struct JsonRpcErrorObject {
    code: i32,
    message: String,
}

impl JsonRpcErrorResponse {
    fn blocked(id: Option<Value>, reason: &str) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            error: JsonRpcErrorObject {
                code: -32003,
                message: format!("[MCP-GUARD BLOCKED] {reason}"),
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

struct SecurityEngine {
    config: AppConfig,
    workspace_root: PathBuf,
}

impl SecurityEngine {
    fn new(config: AppConfig) -> Self {
        let current_dir = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Self {
            config,
            workspace_root: current_dir,
        }
    }

    fn inspect_tool_call(&self, tool_name: &str, args: &Option<Value>) -> PolicyDecision {
        let args_str = match args {
            Some(v) => v.to_string(),
            None => String::new(),
        };

        for pattern in &self.config.filesystem.blocked_patterns {
            if args_str.contains(pattern) {
                return PolicyDecision::Block(format!(
                    "Pattern '{pattern}' is prohibited by policy"
                ));
            }
        }

        if self.config.filesystem.block_path_traversal {
            if args_str.contains("../") || args_str.contains("..\\") {
                return PolicyDecision::Block("Path traversal ('../') attempt detected".into());
            }

            if let Some(Value::Object(map)) = args {
                if let Some(Value::String(path_val)) = map.get("path") {
                    let candidate = PathBuf::from(path_val);
                    let full_path = if candidate.is_relative() {
                        self.workspace_root.join(candidate)
                    } else {
                        candidate
                    };

                    if let Ok(canonical) = full_path.canonicalize() {
                        if !canonical.starts_with(&self.workspace_root) {
                            return PolicyDecision::Block(format!(
                                "Resolved path '{path_val}' escapes workspace root"
                            ));
                        }
                    }
                }
            }
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

        if let Ok(serialized) = serde_json::to_string(&event) {
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.config.audit.log_file)
                .await
            {
                let _ = file.write_all(format!("{serialized}\n").as_bytes()).await;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw_args: Vec<String> = env::args().collect();
    let separator_pos = raw_args.iter().position(|r| r == "--");

    let target_args = match separator_pos {
        Some(pos) if pos + 1 < raw_args.len() => &raw_args[pos + 1..],
        _ => {
            eprintln!("Usage: mcp-guard -- <command> [args...]");
            eprintln!("Example: mcp-guard -- npx -y @modelcontextprotocol/server-filesystem /workspace");
            std::process::exit(1);
        }
    };

    let program = &target_args[0];
    let cmd_args = &target_args[1..];

    let config = AppConfig::load();
    let engine = SecurityEngine::new(config);

    let mut child = Command::new(program)
        .args(cmd_args)
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

                                let error_reply = JsonRpcErrorResponse::blocked(rpc.id, &reason);
                                let json_bytes = serde_json::to_vec(&error_reply).unwrap();
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
            eprintln!("\n[mcp-guard] Interrupted. Shutting down gracefully...");
        }
    }

    stdout_forwarder.abort();
    let _ = child.kill().await;

    Ok(())
}