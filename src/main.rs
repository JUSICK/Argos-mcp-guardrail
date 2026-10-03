use std::env;
use std::path::PathBuf;
use std::process::Stdio;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{self, AsyncWriteExt};
use tokio::process::Command;
use tokio_util::codec::{FramedRead, LinesCodec};

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
                code: -32003, // Custom JSON-RPC error code
                message: format!("[MCP-GATEWAY BLOCKED] {reason}"),
            },
        }
    }
}

enum PolicyDecision {
    Allow,
    Block(String),
}

struct SecurityEngine {
    workspace_root: PathBuf,
}

impl SecurityEngine {
    fn new() -> Self {
        let current_dir = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Self {
            workspace_root: current_dir,
        }
    }

    fn inspect_tool_call(&self, tool_name: &str, args: &Option<Value>) -> PolicyDecision {
        let args_str = match args {
            Some(v) => v.to_string(),
            None => String::new(),
        };

        let sensitive_patterns = [".env", ".ssh", "id_rsa", "id_ed25519", "credentials", "id_dsa"];
        for pattern in sensitive_patterns {
            if args_str.contains(pattern) {
                return PolicyDecision::Block(format!(
                    "Access to sensitive file or pattern '{pattern}' is denied."
                ));
            }
        }

        if args_str.contains("../") || args_str.contains("..\\") {
            return PolicyDecision::Block("Path traversal pattern ('../') detected.".into());
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
                            "Path '{}' points outside workspace directory.",
                            path_val
                        ));
                    }
                }
            }
        }

        if tool_name == "execute_command" || tool_name == "bash" || tool_name == "sh" {
            let dangerous_commands = [
                "rm -rf /",
                "mkfs",
                ":(){ :|:& };:",
                "dd if=",
                "> /dev/sda",
                "chmod -R 777 /",
            ];
            for cmd in dangerous_commands {
                if args_str.contains(cmd) {
                    return PolicyDecision::Block(format!(
                        "Destructive shell payload '{cmd}' is prohibited."
                    ));
                }
            }
        }

        PolicyDecision::Allow
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let raw_args: Vec<String> = env::args().collect();

    let separator_pos = raw_args.iter().position(|r| r == "--");

    let target_args = match separator_pos {
        Some(pos) if pos + 1 < raw_args.len() => &raw_args[pos + 1..],
        _ => {
            eprintln!("Usage: mcp-gateway -- <command> [args...]");
            eprintln!("Example: mcp-gateway -- npx -y @modelcontextprotocol/server-filesystem /workspace");
            std::process::exit(1);
        }
    };

    let program = &target_args[0];
    let cmd_args = &target_args[1..];

    let mut child = Command::new(program)
        .args(cmd_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("Failed to spawn target process '{program}': {e}"))?;

    let mut child_stdin = child.stdin.take().expect("Failed to open child stdin");
    let child_stdout = child.stdout.take().expect("Failed to open child stdout");

    let engine = SecurityEngine::new();

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
                            .unwrap_or_default();

                        let args = rpc.params.as_ref().and_then(|p| p.get("arguments")).cloned();

                        if let PolicyDecision::Block(reason) = engine.inspect_tool_call(tool_name, &args) {
                            let error_reply = JsonRpcErrorResponse::blocked(rpc.id, &reason);
                            let json_bytes = serde_json::to_vec(&error_reply).unwrap();

                            let mut out = io::stdout();
                            let _ = out.write_all(&json_bytes).await;
                            let _ = out.write_all(b"\n").await;
                            let _ = out.flush().await;
                            continue;
                        }
                    }
                }

                let _ = child_stdin.write_all(line.as_bytes()).await;
                let _ = child_stdin.write_all(b"\n").await;
                let _ = child_stdin.flush().await;
            }
        } => {}

        _ = tokio::signal::ctrl_c() => {
            eprintln!("\n[mcp-gateway] Interrupted. Shutting down gracefully...");
        }
    }

    stdout_forwarder.abort();

    let _ = child.kill().await;

    Ok(())
}