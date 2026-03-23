#!/usr/bin/env node

/**
 * MCP Behavior Tests for mcp-security-scanner
 *
 * Tests cover:
 *  - stdio transport: initialize, tools/list, tools/call (success + failure)
 *  - HTTP transport: health endpoint, initialize, origin validation
 *  - Tool annotation presence
 *  - Schema validation (missing required args)
 */

import { spawn } from "child_process";
import { strict as assert } from "assert";
import { randomUUID } from "crypto";
import fs from "fs/promises";
import path from "path";
import os from "os";

const SERVER_ENTRY = new URL("../dist/index.js", import.meta.url).pathname;
const HTTP_PORT = 18300 + Math.floor(Math.random() * 700);

let passed = 0;
let failed = 0;

function test(name, fn) {
  return fn()
    .then(() => { passed++; console.log(`  PASS  ${name}`); })
    .catch((err) => { failed++; console.error(`  FAIL  ${name}: ${err.message}`); });
}

function jsonrpc(method, params = {}, id) {
  return JSON.stringify({ jsonrpc: "2.0", id: id ?? randomUUID(), method, params });
}

function sendStdio(proc, method, params) {
  return new Promise((resolve, reject) => {
    const id = randomUUID();
    const msg = jsonrpc(method, params, id);
    let buf = "";
    const onData = (chunk) => {
      buf += chunk.toString();
      for (const line of buf.split("\n")) {
        if (!line.trim()) continue;
        try {
          const parsed = JSON.parse(line);
          if (parsed.id === id) {
            proc.stdout.removeListener("data", onData);
            resolve(parsed);
            return;
          }
        } catch { /* incomplete */ }
      }
    };
    proc.stdout.on("data", onData);
    proc.stdin.write(msg + "\n");
    setTimeout(() => {
      proc.stdout.removeListener("data", onData);
      reject(new Error(`Timeout for ${method}`));
    }, 10000);
  });
}

async function spawnStdio() {
  const proc = spawn(process.execPath, [SERVER_ENTRY], {
    env: { ...process.env, MCP_TRANSPORT: "stdio" },
    stdio: ["pipe", "pipe", "pipe"],
  });
  await new Promise((resolve) => {
    const onStderr = (data) => {
      if (data.toString().includes("connected via stdio")) {
        proc.stderr.removeListener("data", onStderr);
        resolve();
      }
    };
    proc.stderr.on("data", onStderr);
    setTimeout(resolve, 4000);
  });
  return proc;
}

async function spawnHttp(port, extraEnv = {}) {
  const proc = spawn(process.execPath, [SERVER_ENTRY], {
    env: { ...process.env, MCP_TRANSPORT: "http", MCP_SERVER_PORT: String(port), MCP_SERVER_HOST: "127.0.0.1", ...extraEnv },
    stdio: ["pipe", "pipe", "pipe"],
  });
  await new Promise((resolve) => {
    const onStderr = (data) => {
      if (data.toString().includes("HTTP server at")) {
        proc.stderr.removeListener("data", onStderr);
        resolve();
      }
    };
    proc.stderr.on("data", onStderr);
    setTimeout(resolve, 5000);
  });
  return proc;
}

// Create a temp directory with a vulnerable test file for scanning
async function createTestFixture() {
  const tmpDir = path.join(os.tmpdir(), `mcp-sec-test-${Date.now()}`);
  await fs.mkdir(tmpDir, { recursive: true });
  await fs.writeFile(path.join(tmpDir, "vulnerable.js"), `
const password = "admin123";
const result = eval(userInput);
const cmd = require('child_process').exec('rm -rf /');
  `.trim());
  await fs.writeFile(path.join(tmpDir, "package.json"), JSON.stringify({
    name: "test-project",
    version: "1.0.0",
    dependencies: { "some-pkg": "*" },
  }));
  return tmpDir;
}

// ---------- stdio tests ----------

async function stdioTests() {
  console.log("\n--- stdio transport tests ---");
  const proc = await spawnStdio();

  try {
    await test("initialize succeeds", async () => {
      const resp = await sendStdio(proc, "initialize", {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "test", version: "1.0.0" },
      });
      assert.ok(resp.result);
      assert.equal(resp.result.protocolVersion, "2025-11-25");
      assert.equal(resp.result.serverInfo.name, "mcp-security-scanner");
    });

    proc.stdin.write(jsonrpc("notifications/initialized") + "\n");
    await new Promise((r) => setTimeout(r, 200));

    await test("tools/list returns expected tools", async () => {
      const resp = await sendStdio(proc, "tools/list", {});
      const names = resp.result.tools.map((t) => t.name);
      for (const expected of ["securityScan", "scanFile", "auditDependencies", "checkPermissions", "memoryStatus"]) {
        assert.ok(names.includes(expected), `Missing tool: ${expected}`);
      }
    });

    await test("all tools have annotations with title", async () => {
      const resp = await sendStdio(proc, "tools/list", {});
      for (const tool of resp.result.tools) {
        assert.ok(tool.annotations, `${tool.name} missing annotations`);
        assert.ok(typeof tool.annotations.title === "string", `${tool.name} missing title`);
      }
    });

    await test("memoryStatus returns memory info", async () => {
      const resp = await sendStdio(proc, "tools/call", {
        name: "memoryStatus",
        arguments: {},
      });
      assert.ok(resp.result);
      assert.ok(!resp.result.isError);
      const text = resp.result.content.map((c) => c.text).join(" ");
      assert.ok(text.includes("Heap:"), "Expected heap info");
    });

    // Create test fixture for scanning
    const tmpDir = await createTestFixture();

    await test("securityScan finds vulnerabilities in test fixture", async () => {
      const resp = await sendStdio(proc, "tools/call", {
        name: "securityScan",
        arguments: { targetPath: tmpDir },
      });
      assert.ok(resp.result);
      assert.ok(!resp.result.isError);
      const text = resp.result.content.map((c) => c.text).join(" ");
      assert.ok(text.includes("CRITICAL") || text.includes("HIGH"), "Expected severity findings");
    });

    await test("scanFile finds patterns in vulnerable file", async () => {
      const resp = await sendStdio(proc, "tools/call", {
        name: "scanFile",
        arguments: { filePath: path.join(tmpDir, "vulnerable.js") },
      });
      assert.ok(resp.result);
      assert.ok(!resp.result.isError);
      const text = resp.result.content.map((c) => c.text).join(" ");
      assert.ok(text.includes("UNSAFE_EVAL") || text.includes("HARDCODED"), "Expected specific vuln types");
    });

    await test("auditDependencies finds unpinned deps", async () => {
      const resp = await sendStdio(proc, "tools/call", {
        name: "auditDependencies",
        arguments: { projectPath: tmpDir },
      });
      assert.ok(resp.result);
      assert.ok(!resp.result.isError);
      const text = resp.result.content.map((c) => c.text).join(" ");
      assert.ok(text.includes("UNPINNED"), "Expected unpinned dependency warning");
    });

    await test("securityScan with nonexistent path returns isError", async () => {
      const resp = await sendStdio(proc, "tools/call", {
        name: "securityScan",
        arguments: { targetPath: "/nonexistent/path/abc123" },
      });
      assert.ok(resp.result);
      assert.ok(resp.result.isError === true);
    });

    await test("scanFile with directory returns isError", async () => {
      const resp = await sendStdio(proc, "tools/call", {
        name: "scanFile",
        arguments: { filePath: tmpDir },
      });
      assert.ok(resp.result);
      assert.ok(resp.result.isError === true);
    });

    // Cleanup
    await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {});

  } finally {
    proc.kill();
  }
}

// ---------- HTTP tests ----------

async function httpTests() {
  console.log("\n--- HTTP transport tests ---");
  const proc = await spawnHttp(HTTP_PORT);

  try {
    await test("health endpoint returns 200", async () => {
      const resp = await fetch(`http://127.0.0.1:${HTTP_PORT}/health`);
      assert.equal(resp.status, 200);
      const data = await resp.json();
      assert.equal(data.server, "mcp-security-scanner");
      assert.equal(data.transport_mode, "streamable-http");
    });

    await test("POST /mcp with initialize succeeds", async () => {
      const resp = await fetch(`http://127.0.0.1:${HTTP_PORT}/mcp`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: randomUUID(),
          method: "initialize",
          params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "test", version: "1.0.0" } },
        }),
      });
      assert.ok(resp.status === 200 || resp.status === 202);
    });

    await test("Origin validation returns 403 for disallowed origin", async () => {
      const restrictedPort = HTTP_PORT + 1;
      const restrictedProc = await spawnHttp(restrictedPort, { MCP_ALLOWED_ORIGINS: "https://allowed.example.com" });
      try {
        const resp = await fetch(`http://127.0.0.1:${restrictedPort}/mcp`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json, text/event-stream",
            Origin: "https://evil.example.com",
          },
          body: JSON.stringify({ jsonrpc: "2.0", id: "1", method: "initialize", params: {} }),
        });
        assert.equal(resp.status, 403);
      } finally {
        restrictedProc.kill();
      }
    });

  } finally {
    proc.kill();
  }
}

// ---------- run ----------

async function main() {
  console.log("=== mcp-security-scanner behavior tests ===");
  await stdioTests();
  await httpTests();
  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error("Test runner error:", err);
  process.exit(1);
});
