# Argos — Project Guide for Claude Code

## What this is
Argos is a small Rust CLI (~450 lines, single `src/main.rs`) that sits between
an MCP client (Claude Desktop, Cursor) and a real MCP tool server. It inspects
`tools/call` JSON-RPC messages on stdio and blocks ones that match configured
rules (path traversal, sensitive file patterns, destructive shell commands)
before they reach the real server. Config lives in `argos.toml`.

This is a **security tool** about to be published on GitHub. Bugs here mean
false confidence for anyone who installs it — correctness and clear
explanation matter more than speed.

## Who you're working with
- The user does not know Rust, and this is their first project using Claude
  Code. Treat every change as a chance to teach, not just to ship.
- The code was originally "vibe-coded" by another AI without line-by-line
  review. Don't assume existing code is correct just because it's there —
  explain what it actually does before judging it.

## The one rule that matters most
**The user is in control. Always.**
- Never edit code, run file-changing `cargo` commands (`fmt` without
  `--check`, `fix`, etc.), commit, or push without first explaining, in plain
  language: what's wrong today, why it matters (ideally a concrete exploit
  scenario), and the specific change being proposed — then wait for explicit
  go-ahead.
- Propose one change at a time, not a batch of unrelated fixes. Batching
  makes it impossible to learn from or sanity-check each decision.
- When a change is approved, explain the Rust involved as if the user has
  never seen Rust — don't assume familiarity with ownership, `Result`/
  `Option`, pattern matching, etc. A sentence or two inline is enough, no
  lectures.
- If something unrelated looks questionable while working on something else,
  flag it and ask — don't fix it as a silent drive-by.
- Read-only exploration (reading files, `cargo check`, `cargo clippy`,
  `cargo test`, `cargo fmt --check`) doesn't need pre-approval. Anything that
  writes to disk or to git does.

## Committing and pushing to GitHub
- Every approved change gets committed and pushed to GitHub — work should
  not pile up uncommitted.
- Commit straight to `main` (no feature branches / PRs) and push to `origin`.
- **Ask every time.** Before each commit, show the files being committed and
  the proposed commit message, and wait for the user's OK. That one OK covers
  both the commit and the push.
- One logical change per commit (e.g. a fix together with its tests), so
  each commit can be read and reverted on its own.
- Before pushing, run `cargo fmt --check`, `cargo clippy -- -D warnings` and
  `cargo test` locally — CI runs the same checks on every push to `main`.
- `CLAUDE.md` itself stays local and is never committed.

## Working style for security review
- State findings as: what the code does today → the concrete bypass/attack →
  why it matters → the fix being proposed. Judge severity by "could this let
  an AI agent, a malicious MCP server, or an attacker escape the sandbox,
  read secrets, or run destructive commands" — that's the entire point of
  this tool existing.
- Don't add comments to `src/main.rs` (code or tests). Explain changes in
  chat instead.
- Prefer small, independently reviewable diffs over a rewrite. The user needs
  to be able to read each diff and actually follow it.
- Don't add defensive code for scenarios that can't occur here — this is a
  local, single-binary stdio pipe, not a network service.

## Project facts worth knowing
- The real git repo root is this directory (`argos/`); remote is
  `https://github.com/JUSICK/Argos-mcp-guardrail.git` (HTTPS via Git
  Credential Manager; this machine has no SSH key for GitHub). The parent `mcp-guard/` folder is not a
  git repo itself.
- `.github/workflows/ci.yml` lives in this repo root. Until it's committed and
  pushed, GitHub Actions doesn't run it — check `git status` before assuming
  CI is protecting `main`.
- CI runs `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test` on
  `ubuntu-latest`. Tests live in a `#[cfg(test)] mod tests` block at the
  bottom of `src/main.rs`.
- Bug fixes are test-first: write tests from the attack description, show
  them failing on the unfixed code, then apply the fix without editing the
  tests.

## Useful commands
- `cargo check` — fast compile check, no binary produced.
- `cargo clippy -- -D warnings` — lint, matches CI.
- `cargo test` — run the tests.
- `cargo build --release` — produce the real binary at `target/release/argos[.exe]`.
