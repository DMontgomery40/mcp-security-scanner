# MCP Security Scanner

MCP server for scanning JavaScript/TypeScript projects for security vulnerabilities. Detects dangerous code patterns, insecure file permissions, risky dependencies, hardcoded credentials, and more.

## Tools

| Tool | Description |
|------|-------------|
| `securityScan` | Full recursive scan of a directory for all vulnerability types |
| `scanFile` | Scan a single JS/TS file for dangerous code patterns |
| `auditDependencies` | Check package.json for risky or unpinned dependencies |
| `checkPermissions` | Detect world-writable or overly permissive files |
| `memoryStatus` | Report scanner process memory usage |

## Detected Vulnerability Types

- Hardcoded credentials, API keys, and tokens (CRITICAL)
- `eval()`, `new Function()`, `document.write` usage (CRITICAL/HIGH)
- Command injection via `child_process` (CRITICAL/HIGH)
- XSS risks via `innerHTML` (HIGH)
- Insecure HTTP connections (MEDIUM)
- Dynamic `require()` (MEDIUM)
- Unpinned/wildcard dependencies (MEDIUM)
- Known risky npm packages (HIGH)
- World-writable file permissions (HIGH)
- Debug logging in production (LOW)

## Quick Start

### Install

```bash
npm install
npm run build
```

### Run locally (stdio)

```bash
node dist/index.js
```

### Run over network (Streamable HTTP)

```bash
MCP_TRANSPORT=http MCP_SERVER_HOST=0.0.0.0 MCP_SERVER_PORT=8100 node dist/index.js
```

## Transport Notes

- `stdio`: default for local MCP clients.
- `http`: modern Streamable HTTP transport. Recommended for network access.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_TRANSPORT` | `stdio` | Transport mode: `stdio` or `http` |
| `MCP_SERVER_HOST` | `0.0.0.0` | HTTP bind address |
| `MCP_SERVER_PORT` | `8100` | HTTP port |
| `MCP_ALLOWED_ORIGINS` | (none) | Comma-separated allowed Origins; returns 403 for others |

## Docker

```bash
# stdio mode (default)
docker build -t mcp-security-scanner .
docker run -it mcp-security-scanner

# HTTP mode
docker run -e MCP_TRANSPORT=http -p 8100:8100 mcp-security-scanner
```

## Usage Examples

### Full project scan

```json
{
  "tool": "securityScan",
  "arguments": {
    "targetPath": "/path/to/project",
    "maxDepth": 5
  }
}
```

### Scan single file

```json
{
  "tool": "scanFile",
  "arguments": {
    "filePath": "/path/to/project/src/auth.js"
  }
}
```

### Audit dependencies

```json
{
  "tool": "auditDependencies",
  "arguments": {
    "projectPath": "/path/to/project"
  }
}
```

---

## Appendix: MCP in Practice (Code Execution, Tool Scale, and Safety)

Last updated: 2026-03-23

### Why This Appendix Exists

Model Context Protocol (MCP) is still one of the most useful interoperability layers for tools and agents. The tradeoff is that large MCP servers can expose many tools, and naive tool-calling can flood context windows with schemas, tool chatter, and irrelevant call traces.

In practice, "more tools" is not always "better outcomes." Tool surface area must be paired with execution patterns that keep token use bounded and behavior predictable.

### The Shift to Code Execution / Code Mode

Recent workflows increasingly move complex orchestration out of chat context and into code execution loops. This reduces repetitive schema tokens and makes tool usage auditable and testable.

Core reading:
- [Cloudflare: Code Mode](https://blog.cloudflare.com/code-mode/)
- [Cloudflare: Code Execution with MCP](https://blog.cloudflare.com/code-execution-with-mcp/)
- [Anthropic: Code Execution with MCP](https://www.anthropic.com/engineering/code-execution-with-mcp)

### Recommended Setup for Power Users

For users who want reproducible and lower-noise MCP usage, start with a codemode-oriented setup:
- [codemode-mcp (jx-codes)](https://github.com/jx-codes/codemode-mcp)
- [UTCP](https://www.utcp.io)

### Client Fit Guide (Short Version)

- Claude Code / Codex / Cursor: strong for direct MCP workflows, but still benefit from narrow tool surfaces.
- Code execution wrappers (TypeScript/Python CLIs): better when tool count is high or task chains are multi-step.
- Hosted chat clients with weaker MCP controls: often safer via pre-wrapped CLIs or gateway tools.

### Prompt Injection: Risks, Impact, and Mitigations

Prompt injection remains an open security problem for tool-using agents. It is manageable, but not "solved."

Primary risks:
- Malicious instructions hidden in tool output or remote content.
- Secret exfiltration and unauthorized external calls.
- Unsafe state changes (destructive file/system/API actions).

Mitigation baseline:
- Least privilege for credentials and tool scopes.
- Allowlist destinations and enforce egress controls.
- Strict input validation and schema enforcement.
- Human confirmation for destructive/high-risk actions.
- Sandboxed execution with resource/time limits.
- Structured logging, audit trails, and replayable runs.
- Output filtering/redaction before model re-ingestion.

Treat every tool output as untrusted input unless explicitly verified.

### MCP Compliance State

This server targets MCP protocol version `2025-11-25` and SDK `@modelcontextprotocol/sdk@^1.27.1`.

| Feature | Status |
|---------|--------|
| stdio transport | Supported (default) |
| Streamable HTTP transport | Supported (`MCP_TRANSPORT=http`) |
| Tool annotations | All tools annotated with title, readOnlyHint, destructiveHint, idempotentHint, openWorldHint |
| Origin validation (HTTP) | 403 on invalid Origin when `MCP_ALLOWED_ORIGINS` is set |
| JSON Schema 2020-12 | Zod-generated schemas |
| Structured tool errors | isError flag with descriptive messages for model self-correction |
