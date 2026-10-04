# Argos (`argos`)

> A lightweight, zero-latency security shim & policy enforcement gateway for Model Context Protocol (MCP) servers.

[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Protocol: MCP](https://img.shields.io/badge/Protocol-MCP-green.svg)](https://modelcontextprotocol.io/)

`argos` acts as a transparent security pipe between AI clients (Claude Desktop, Cursor) and underlying MCP tool servers. Inspired by the zero-friction philosophy of Quad9/Pi-hole, it inspects raw JSON-RPC traffic on the fly and deterministically blocks unauthorized file access, path traversal attacks, and destructive commands before they reach your system.

---

## Features

- **Sub-millisecond Overhead:** Built with pure Rust and Tokio asynchronous streams. Zero perceptible lag for the agent or developer.
- **Path Traversal Sandboxing:** Enforces strict workspace boundaries via OS path canonicalization and `../` stripping.
- **Secret & Sensitive File Shield:** Block access to `.env`, private keys (`id_rsa`, `id_ed25519`), and cloud credentials.
- **Destructive Command Blocker:** Intercepts dangerous terminal commands (`rm -rf`, disk formatters, fork bombs).
- **Local Audit Logging:** Records blocked and allowed actions into a structured, JSON-lines log (`argos-audit.log`) without cloud telemetry.
- **Flexible Configuration:** Declarative rule customization via `argos.toml`.

---

## Quick Start

### 1. Build from source

```bash
git clone [https://github.com/YOUR_USERNAME/Argos-mcp-guardrail.git](https://github.com/YOUR_USERNAME/Argos-mcp-guardrail.git)
cd Argos-mcp-guardrail
cargo build --release
```
The compiled binary will be located at target/release/argos.


### 2. Configure policies (argos.toml)
Create a argos.toml file in your workspace:

```[filesystem]
blocked_patterns = [".env", ".ssh", "id_rsa", "id_ed25519", "credentials"]
block_path_traversal = false

[commands]
blocked_commands = ["rm -rf", "mkfs", ":(){ :|:& };:", "chmod -R 777"]

[audit]
enabled = true
log_allowed = false
log_file = "argos-audit.log"
```

### 3. Integrate with Claude Desktop or Cursor
Update your claude_desktop_config.json:

```{
  "mcpServers": {
    "filesystem": {
      "command": "/path/to/argos",
      "args": [
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/path/to/allowed/workspace"
      ]
    }
  }
}
```

### 4. How it works:

```[ AI Client (Claude / Cursor) ]
              │
              │ stdin / stdout (JSON-RPC)
              ▼
   ┌───────────────────────┐
   │         argos         │  <── Inspects tools/call in <0.2ms
   └───────────────────────┘
         │           │
   (If Allowed)  (If Blocked) ──> Returns JSON-RPC Error & logs event
         │
         ▼
[ Real MCP Tool Server ]
```


MIT License. Free for personal and commercial use.