# Argos

Argos sits between an MCP client (Claude Desktop, Cursor) and an MCP server.
It reads every `tools/call` request and refuses the ones that reach outside
your workspace, touch secrets like `.env` or SSH keys, or run commands like
`rm -rf`. Everything else goes through unchanged.

It's a single binary with no network access, configured by one TOML file.

<img width="1734" height="875" alt="Argos blocking a tool call in Claude Desktop" src="https://github.com/user-attachments/assets/3554e752-14a8-4893-b7af-f4f81800e170" />

## What it blocks

- **Paths outside the workspace.** Paths are resolved before they're
  checked (`..`, symlinks, junctions, files that don't exist yet), so
  `../` tricks and links pointing elsewhere don't get through.
- **Sensitive files**: anything matching `blocked_patterns`. By default
  that's `.env`, `.ssh`, `id_rsa`, `id_ed25519`, `credentials`, `.npmrc`,
  `.aws` and `.git-credentials`, matched case-insensitively.
- **Destructive commands**: anything containing one of `blocked_commands`.
  By default that's `rm -rf`, `rm -fr`, `mkfs`, `dd if=`, `chmod -R 777` and
  the classic fork bomb. Case and extra spaces don't matter.

A blocked call never reaches the server. The client gets a tool result with
`isError: true` that says what rule it hit.

This is pattern matching, not a sandbox. It keeps an agent from wandering
into places it shouldn't, but a command can always be phrased in a way the
patterns don't catch, and it does nothing about a server that is itself
malicious.

## Install

### Download

Grab the file for your system from
[Releases](https://github.com/JUSICK/Argos-mcp-guardrail/releases):

- **Windows**: `argos.exe`, or `argos-windows-x86_64.zip`
- **Linux**: `argos-linux-x86_64.tar.gz` (statically linked, runs on any distro)

  ```sh
  tar -xzf argos-linux-x86_64.tar.gz
  chmod +x argos
  ```

- **macOS** (Apple Silicon and Intel): `argos-macos-universal.tar.gz`. The
  binary isn't signed by Apple, so clear the quarantine flag once before
  the first run:

  ```sh
  tar -xzf argos-macos-universal.tar.gz
  xattr -d com.apple.quarantine argos
  ```

### Build from source

```sh
git clone https://github.com/JUSICK/Argos-mcp-guardrail.git
cd Argos-mcp-guardrail
cargo build --release
```

The binary ends up in `target/release/argos` (`argos.exe` on Windows).

## Use it with Claude Desktop

In `claude_desktop_config.json`, run Argos instead of the server and give it
the server command after `--`. Argos's own options go before `--`.

Windows:

```json
{
  "mcpServers": {
    "Argos": {
      "command": "C:\\path\\to\\argos.exe",
      "args": [
        "--workspace", "C:\\Users\\you\\projects\\my-project",
        "--",
        "npx.cmd", "-y", "@modelcontextprotocol/server-filesystem",
        "C:\\Users\\you\\projects\\my-project"
      ]
    }
  }
}
```

macOS / Linux:

```json
{
  "mcpServers": {
    "Argos": {
      "command": "/usr/local/bin/argos",
      "args": [
        "--workspace", "/Users/you/projects/my-project",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem",
        "/Users/you/projects/my-project"
      ]
    }
  }
}
```

Then restart Claude Desktop. Cursor uses the same `mcpServers` format in its
`mcp.json`.

`--workspace` is the folder Argos keeps the agent inside. If you leave it
out, Argos uses the last argument after `--` that is an existing directory.
It refuses to start if there isn't one, or if that would make the workspace
`/` or `C:\`. Either way it prints the folder it picked to stderr, which
shows up in the client's MCP log.

You can run several Argos entries side by side, for example `Argos-Backend`
and `Argos-Frontend` with different workspaces.

## Configuration

Argos reads `argos.toml` from the folder its executable is in. Without one
it uses the defaults below. If the file has a syntax error or a key Argos
doesn't recognise, it prints the error and exits, so a typo can't quietly
turn your rules off.

Keep the executable, and with it `argos.toml`, outside the workspace it
protects. Otherwise the agent could edit its own rules.

This is the full default config:

```toml
[filesystem]
# Block paths that resolve to somewhere outside the workspace.
block_path_traversal = true

# Arguments with these names are treated as paths (a string or a list of
# strings). Any argument with one of these names counts, even if the tool
# means something else by it, e.g. `to`.
path_keys = ["path", "uri", "paths", "source", "destination", "src", "dest",
             "target", "from", "to", "file", "filename", "directory", "dir"]

# Checked against resolved paths and against the raw arguments, so a call
# that merely mentions `.env` in its content is blocked too.
blocked_patterns = [".env", ".ssh", "id_rsa", "id_ed25519", "credentials",
                    ".npmrc", ".aws", ".git-credentials"]

# Text matching one of these is ignored when checking blocked_patterns,
# so `.env.example` is readable while `.env` isn't.
allowed_patterns = [".env.example", ".env.sample", ".env.template"]

[commands]
# true: check every tool call for blocked commands.
# false: only check the tools listed in shell_tools.
check_all_tools = true
shell_tools = ["execute_command", "bash", "sh", "shell", "run_shell",
               "run_command", "terminal", "exec", "powershell", "cmd"]

blocked_commands = ["rm -rf", "rm -fr", "mkfs", ":(){ :|:& };:",
                    "dd if=", "chmod -R 777"]

[audit]
enabled = true
# Also log calls that were allowed.
log_allowed = false
# A bare file name goes next to the executable; an absolute path is used as is.
log_file = "argos-audit.log"
```

A list you set replaces the default list rather than adding to it. If you
add your own `blocked_patterns`, copy in the defaults you want to keep.

## Audit log

Every blocked call, and every allowed one if `log_allowed = true`, is
appended to the log as one line of JSON:

```json
{"timestamp":"2026-10-13T20:47:31.201262620+00:00","argos_pid":2668,"server_pid":2692,"event_type":"BLOCKED","tool_name":"read_file","reason":"Resolved target path escapes workspace boundary: /etc/passwd","arguments":{"path":"/etc/passwd"}}
```

Only path arguments are written out. Every other value, such as file
contents or commands, is replaced with `[REDACTED]`, so a blocked attempt
to write a secret doesn't end up in the log. `argos_pid` and `server_pid`
tell apart sessions that share one log file.

On macOS and Linux the file is created readable only by you. On Windows it
gets the permissions of the folder it's in.

## How it works

```
MCP client  <── stdin/stdout ──>  argos  <── stdin/stdout ──>  MCP server
                                    │
                         blocked: reply to the client
                         and write the audit log
```

Argos starts the server as a child process and relays its stdin and stdout
line by line. Only `tools/call` requests are inspected; everything else,
including all of the server's replies, passes through as is.

A line longer than 8 MiB ends the session instead of being buffered. When
the client disconnects, Argos closes the server's input and waits up to 30
seconds for any replies still on their way before stopping it.

## License

MIT
