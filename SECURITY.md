# Security Policy

Argos is a security tool, so bypasses and bugs in it matter. Thank you for
taking the time to report them.

## Reporting a vulnerability

Please report it privately through GitHub:

**[Report a vulnerability](https://github.com/JUSICK/Argos-mcp-guardrail/security/advisories/new)**

Please don't open a public issue for something that lets a tool call get past
Argos in a way the README doesn't already describe. Include:

- The Argos version (`Cargo.toml` or the release you downloaded) and your OS.
- Your `argos.toml`, or say that you used the defaults.
- The exact `tools/call` request (JSON) that got through, and what you
  expected Argos to do.
- If you can, a failing test or a short reproduction.

This is a small project maintained by one person. I aim to acknowledge reports
within a week and to fix confirmed issues in the next release. I'm happy to
credit you in the release notes unless you'd rather stay anonymous.

## What counts as a vulnerability

- A request that should be blocked by the default rules but is forwarded to the
  server, for example a path trick that escapes the workspace or reaches a
  blocked file.
- A way to make Argos crash, hang or stop checking requests (for example a
  malformed message that turns checking off for the rest of the session).
- Secrets from a blocked or allowed call ending up in `argos-audit.log`.
- A config that Argos accepts but silently ignores.

## What doesn't

The README's [Limitations](README.md#limitations) section lists what Argos is
not designed to stop. These are known and aren't treated as vulnerabilities,
though ideas for improving them are welcome as normal issues:

- Tool calls that never go through Argos, such as a client's built-in shell or
  file tools, or MCP servers you didn't wrap.
- Commands that avoid the configured `blocked_commands` text (for example
  `rm -r -f`, or a script that deletes files). Adding more patterns is a
  normal feature request.
- Harm done by a malicious or compromised MCP server on its own.
- Anything that requires write access to `argos.toml` or the Argos executable.

## Supported versions

Only the latest release gets security fixes.
