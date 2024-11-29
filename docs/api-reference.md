---
layout: default
title: API Reference - MCP Security Scanner
---

# API Reference

## Classes

### SecurityScanner

Main scanner class that performs security checks.

```javascript
import { SecurityScanner } from 'mcp-security-scanner';

const scanner = new SecurityScanner();
```

#### Methods

- `scanForVulnerabilities(context)`
- `scanMemoryVulnerabilities(context, results)`
- `scanFileSystemVulnerabilities(context, results)`
- `scanPluginSystemVulnerabilities(context, results)`

### MCPSecurityServer

WebSocket server implementation.

```javascript
import { MCPSecurityServer } from 'mcp-security-scanner';

const server = new MCPSecurityServer(3000);
server.start();
```