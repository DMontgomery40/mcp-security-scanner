#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express from "express";
import { z } from "zod";
import fs from "fs/promises";
import path from "path";
import crypto from "crypto";

const transportType = (process.argv[2] || process.env.MCP_TRANSPORT || "stdio").toLowerCase();
const serverHost = process.env.MCP_SERVER_HOST || "0.0.0.0";
const serverPort = parseInt(process.env.MCP_SERVER_PORT || "8100");
const serverVersion = process.env.npm_package_version || "1.0.0";

function parseCsvEnv(value: string | undefined, fallback: string[] = []): string[] {
  if (!value) return fallback;
  return value.split(/[,\s]+/).map(v => v.trim()).filter(Boolean);
}

// ---------- Vulnerability types ----------

interface Vulnerability {
  type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  details: string;
  location: string;
  recommendation: string;
}

interface ScanResult {
  vulnerabilities: Vulnerability[];
  timestamp: string;
  scanDuration: number;
  error?: { message: string };
}

// ---------- Scanner logic (ported from original main.js) ----------

const WEAK_PASSWORDS = ["admin", "password", "123456", "default", "root", "test", "guest", "letmein"];
const DANGEROUS_PATTERNS = [
  { pattern: /eval\s*\(/, type: "UNSAFE_EVAL", severity: "CRITICAL" as const, recommendation: "Replace eval() with safer alternatives like JSON.parse() or Function constructors with validation" },
  { pattern: /exec\s*\(/, type: "COMMAND_INJECTION", severity: "CRITICAL" as const, recommendation: "Use parameterized commands or execFile with argument arrays instead of exec" },
  { pattern: /child_process/, type: "COMMAND_EXECUTION", severity: "HIGH" as const, recommendation: "Audit all child_process usage; prefer execFile over exec; validate all inputs" },
  { pattern: /innerHTML\s*=/, type: "XSS_RISK", severity: "HIGH" as const, recommendation: "Use textContent or sanitize HTML before inserting into DOM" },
  { pattern: /document\.write/, type: "XSS_RISK", severity: "HIGH" as const, recommendation: "Avoid document.write; use DOM APIs instead" },
  { pattern: /new\s+Function\s*\(/, type: "UNSAFE_FUNCTION_CONSTRUCTOR", severity: "HIGH" as const, recommendation: "Avoid dynamic function construction from strings" },
  { pattern: /process\.env\.\w+/, type: "ENV_EXPOSURE", severity: "MEDIUM" as const, recommendation: "Validate and sanitize environment variable usage; do not expose in client code" },
  { pattern: /http:\/\//, type: "INSECURE_PROTOCOL", severity: "MEDIUM" as const, recommendation: "Use HTTPS for all network connections" },
  { pattern: /require\s*\(\s*[^'"]\s*\)/, type: "DYNAMIC_REQUIRE", severity: "MEDIUM" as const, recommendation: "Avoid dynamic require; use static imports with explicit module paths" },
  { pattern: /\.readFile(Sync)?\s*\(/, type: "FILE_READ", severity: "INFO" as const, recommendation: "Ensure file paths are validated and cannot be user-controlled" },
  { pattern: /\.writeFile(Sync)?\s*\(/, type: "FILE_WRITE", severity: "MEDIUM" as const, recommendation: "Validate file write paths; avoid writing user-controlled content without sanitization" },
  { pattern: /console\.(log|debug|info)\s*\(/, type: "DEBUG_LOGGING", severity: "LOW" as const, recommendation: "Remove debug logging in production code; use structured logging instead" },
  { pattern: /password\s*[:=]\s*['"][^'"]+['"]/, type: "HARDCODED_CREDENTIAL", severity: "CRITICAL" as const, recommendation: "Never hardcode credentials; use environment variables or secret management" },
  { pattern: /api[_-]?key\s*[:=]\s*['"][^'"]+['"]/, type: "HARDCODED_API_KEY", severity: "CRITICAL" as const, recommendation: "Store API keys in environment variables or secret management systems" },
  { pattern: /token\s*[:=]\s*['"][a-zA-Z0-9_\-.]{20,}['"]/, type: "HARDCODED_TOKEN", severity: "CRITICAL" as const, recommendation: "Store tokens securely; never commit them to source control" },
];

const JS_TS_EXTENSIONS = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".mts", ".cjs", ".cts"]);
const EXCLUDED_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", "coverage", "__pycache__", ".tox"]);

async function collectFiles(basePath: string, maxDepth: number, currentDepth = 0): Promise<string[]> {
  if (currentDepth > maxDepth) return [];
  const files: string[] = [];
  try {
    const entries = await fs.readdir(basePath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(basePath, entry.name);
      if (entry.isDirectory()) {
        if (!EXCLUDED_DIRS.has(entry.name)) {
          files.push(...await collectFiles(fullPath, maxDepth, currentDepth + 1));
        }
      } else if (entry.isFile() && JS_TS_EXTENSIONS.has(path.extname(entry.name))) {
        files.push(fullPath);
      }
    }
  } catch (err: any) {
    // Permission denied or missing dir -- skip silently
  }
  return files;
}

async function scanFileContent(filePath: string): Promise<Vulnerability[]> {
  const vulns: Vulnerability[] = [];
  try {
    const content = await fs.readFile(filePath, "utf8");
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const pattern of DANGEROUS_PATTERNS) {
        if (pattern.pattern.test(line)) {
          vulns.push({
            type: pattern.type,
            severity: pattern.severity,
            details: `Pattern match on line ${i + 1}: ${line.trim().slice(0, 120)}`,
            location: `${filePath}:${i + 1}`,
            recommendation: pattern.recommendation,
          });
        }
      }
    }
  } catch {
    // unreadable file -- skip
  }
  return vulns;
}

async function scanFilePermissions(basePath: string): Promise<Vulnerability[]> {
  const vulns: Vulnerability[] = [];
  try {
    const entries = await fs.readdir(basePath, { withFileTypes: true });
    for (const entry of entries) {
      if (EXCLUDED_DIRS.has(entry.name)) continue;
      const fullPath = path.join(basePath, entry.name);
      try {
        const stats = await fs.stat(fullPath);
        // Check for world-writable files
        if ((stats.mode & 0o002) !== 0) {
          vulns.push({
            type: "WORLD_WRITABLE",
            severity: "HIGH",
            details: `File is world-writable (mode: ${(stats.mode & 0o7777).toString(8)})`,
            location: fullPath,
            recommendation: "Restrict file permissions to owner/group only",
          });
        }
      } catch { /* skip */ }
    }
  } catch { /* skip */ }
  return vulns;
}

function scanMemory(): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  const usage = process.memoryUsage();
  const heapMb = Math.round(usage.heapUsed / 1024 / 1024);
  if (heapMb > 100) {
    vulns.push({
      type: "HIGH_MEMORY_USAGE",
      severity: "HIGH",
      details: `Scanner process heap usage: ${heapMb}MB`,
      location: "process.memoryUsage()",
      recommendation: "Investigate memory leaks in long-running processes",
    });
  }
  return vulns;
}

async function scanDependencies(basePath: string): Promise<Vulnerability[]> {
  const vulns: Vulnerability[] = [];
  const pkgPath = path.join(basePath, "package.json");
  try {
    const raw = await fs.readFile(pkgPath, "utf8");
    const pkg = JSON.parse(raw) as Record<string, unknown>;
    const deps = { ...(pkg.dependencies as Record<string, string> || {}), ...(pkg.devDependencies as Record<string, string> || {}) };

    // Check for known risky packages
    const riskyPackages: Record<string, string> = {
      "event-stream": "Known supply-chain attack vector (flatmap-stream incident)",
      "ua-parser-js": "Had crypto-mining malware injected in v0.7.29+",
      "coa": "Compromised versions published in Nov 2021",
      "rc": "Compromised versions published in Nov 2021",
    };
    for (const [name, reason] of Object.entries(riskyPackages)) {
      if (name in deps) {
        vulns.push({
          type: "RISKY_DEPENDENCY",
          severity: "HIGH",
          details: `Package "${name}" is listed as a dependency. ${reason}`,
          location: pkgPath,
          recommendation: `Audit "${name}" usage and consider alternatives`,
        });
      }
    }

    // Check for wildcard versions
    for (const [name, version] of Object.entries(deps)) {
      if (version === "*" || version === "latest") {
        vulns.push({
          type: "UNPINNED_DEPENDENCY",
          severity: "MEDIUM",
          details: `Package "${name}" uses unpinned version "${version}"`,
          location: pkgPath,
          recommendation: "Pin dependencies to specific versions or semver ranges",
        });
      }
    }
  } catch {
    // no package.json or parse error -- skip
  }
  return vulns;
}

async function runFullScan(targetPath: string, maxDepth: number): Promise<ScanResult> {
  const start = Date.now();
  const vulnerabilities: Vulnerability[] = [];

  // 1. Memory scan
  vulnerabilities.push(...scanMemory());

  // 2. File permission scan
  vulnerabilities.push(...await scanFilePermissions(targetPath));

  // 3. Dependency scan
  vulnerabilities.push(...await scanDependencies(targetPath));

  // 4. Source code pattern scan
  const files = await collectFiles(targetPath, maxDepth);
  for (const file of files) {
    vulnerabilities.push(...await scanFileContent(file));
  }

  return {
    vulnerabilities,
    timestamp: new Date().toISOString(),
    scanDuration: Date.now() - start,
  };
}

// ---------- MCP Server ----------

async function main() {
  console.error(`Initializing MCP Security Scanner with ${transportType} transport...`);

  const server = new McpServer(
    { name: "mcp-security-scanner", version: serverVersion },
    { capabilities: { resources: {}, tools: {} } }
  );

  // --- Tool: Full Security Scan ---
  server.tool(
    "securityScan",
    {
      targetPath: z.string().describe("Absolute path to the directory to scan for vulnerabilities"),
      maxDepth: z.number().int().min(1).max(20).optional().describe("Maximum directory traversal depth (default: 5)"),
    },
    {
      title: "Full Security Vulnerability Scan",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    async ({ targetPath, maxDepth }) => {
      try {
        const resolvedPath = path.resolve(targetPath);
        const stat = await fs.stat(resolvedPath);
        if (!stat.isDirectory()) {
          return { content: [{ type: "text", text: `Error: "${resolvedPath}" is not a directory.` }], isError: true };
        }
        const result = await runFullScan(resolvedPath, maxDepth ?? 5);

        const bySeverity: Record<string, number> = {};
        for (const v of result.vulnerabilities) {
          bySeverity[v.severity] = (bySeverity[v.severity] || 0) + 1;
        }
        const summary = Object.entries(bySeverity).map(([s, c]) => `${s}: ${c}`).join(", ") || "No vulnerabilities found";

        return {
          content: [
            { type: "text", text: `Scan complete in ${result.scanDuration}ms. Scanned: ${resolvedPath}` },
            { type: "text", text: `Summary: ${summary}` },
            { type: "text", text: JSON.stringify(result, null, 2) },
          ],
        };
      } catch (err: any) {
        return { content: [{ type: "text", text: `Error: ${err.message}` }], isError: true };
      }
    }
  );

  // --- Tool: Scan Single File ---
  server.tool(
    "scanFile",
    {
      filePath: z.string().describe("Absolute path to a JavaScript/TypeScript file to scan"),
    },
    {
      title: "Scan Single File for Vulnerabilities",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    async ({ filePath }) => {
      try {
        const resolvedPath = path.resolve(filePath);
        const stat = await fs.stat(resolvedPath);
        if (!stat.isFile()) {
          return { content: [{ type: "text", text: `Error: "${resolvedPath}" is not a file.` }], isError: true };
        }
        const vulns = await scanFileContent(resolvedPath);
        if (vulns.length === 0) {
          return { content: [{ type: "text", text: `No vulnerabilities found in ${resolvedPath}` }] };
        }
        return {
          content: [
            { type: "text", text: `Found ${vulns.length} issue(s) in ${resolvedPath}` },
            { type: "text", text: JSON.stringify(vulns, null, 2) },
          ],
        };
      } catch (err: any) {
        return { content: [{ type: "text", text: `Error: ${err.message}` }], isError: true };
      }
    }
  );

  // --- Tool: Dependency Audit ---
  server.tool(
    "auditDependencies",
    {
      projectPath: z.string().describe("Absolute path to a project directory containing package.json"),
    },
    {
      title: "Audit Project Dependencies",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    async ({ projectPath }) => {
      try {
        const resolvedPath = path.resolve(projectPath);
        const vulns = await scanDependencies(resolvedPath);
        if (vulns.length === 0) {
          return { content: [{ type: "text", text: `No dependency issues found in ${resolvedPath}` }] };
        }
        return {
          content: [
            { type: "text", text: `Found ${vulns.length} dependency issue(s)` },
            { type: "text", text: JSON.stringify(vulns, null, 2) },
          ],
        };
      } catch (err: any) {
        return { content: [{ type: "text", text: `Error: ${err.message}` }], isError: true };
      }
    }
  );

  // --- Tool: Check File Permissions ---
  server.tool(
    "checkPermissions",
    {
      targetPath: z.string().describe("Absolute path to a directory to check for insecure file permissions"),
    },
    {
      title: "Check File Permissions",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    async ({ targetPath }) => {
      try {
        const resolvedPath = path.resolve(targetPath);
        const vulns = await scanFilePermissions(resolvedPath);
        if (vulns.length === 0) {
          return { content: [{ type: "text", text: `No permission issues found in ${resolvedPath}` }] };
        }
        return {
          content: [
            { type: "text", text: `Found ${vulns.length} permission issue(s)` },
            { type: "text", text: JSON.stringify(vulns, null, 2) },
          ],
        };
      } catch (err: any) {
        return { content: [{ type: "text", text: `Error: ${err.message}` }], isError: true };
      }
    }
  );

  // --- Tool: Memory Status ---
  server.tool(
    "memoryStatus",
    {},
    {
      title: "Check Scanner Memory Usage",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
    async () => {
      const usage = process.memoryUsage();
      const vulns = scanMemory();
      return {
        content: [
          { type: "text", text: `Heap: ${Math.round(usage.heapUsed / 1024 / 1024)}MB / ${Math.round(usage.heapTotal / 1024 / 1024)}MB` },
          { type: "text", text: `RSS: ${Math.round(usage.rss / 1024 / 1024)}MB` },
          ...(vulns.length > 0
            ? [{ type: "text" as const, text: `Warnings: ${JSON.stringify(vulns)}` }]
            : [{ type: "text" as const, text: "Memory usage within normal range." }]),
        ],
      };
    }
  );

  // --- Transport Selection ---
  const allowedOrigins = parseCsvEnv(process.env.MCP_ALLOWED_ORIGINS);

  switch (transportType) {
    case "stdio": {
      const transport = new StdioServerTransport();
      await server.connect(transport);
      console.error("MCP Security Scanner connected via stdio.");
      await new Promise(() => {});
      break;
    }

    case "http": {
      const app = express();
      app.use(express.json({ limit: "10mb" }));

      // Origin validation per MCP spec
      app.use("/mcp", (req, res, next) => {
        const origin = req.headers.origin;
        if (origin && allowedOrigins.length > 0 && !allowedOrigins.includes(origin)) {
          res.status(403).json({ error: "Forbidden: invalid Origin" });
          return;
        }
        next();
      });

      const streamableTransport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
      });
      await server.connect(streamableTransport);

      app.all("/mcp", async (req, res) => {
        try {
          await streamableTransport.handleRequest(req as any, res as any, req.body);
        } catch (error: any) {
          console.error("Failed to handle HTTP MCP request:", error);
          if (!res.headersSent) {
            res.status(500).json({ error: error.message || "internal error" });
          }
        }
      });

      app.get("/health", (_req, res) => {
        res.json({
          status: "healthy",
          transport_mode: "streamable-http",
          server: "mcp-security-scanner",
          version: serverVersion,
        });
      });

      app.listen(serverPort, serverHost, () => {
        console.error(`MCP Security Scanner HTTP server at http://${serverHost}:${serverPort}/mcp`);
        console.error(`Health check at http://${serverHost}:${serverPort}/health`);
      });
      break;
    }

    default:
      console.error(`Unknown transport: ${transportType}. Use: stdio, http`);
      process.exit(1);
  }

  console.error("MCP Security Scanner initialized.");
}

main().catch((error) => {
  console.error("Unhandled error:", error);
  process.exit(1);
});
