---
layout: default
title: MCP Security Scanner
---

# MCP Security Scanner

A comprehensive security vulnerability scanner designed specifically for Model Context Protocol (MCP) servers and plugins.

## Features

### Security Scanning

- **Memory Vulnerability Detection**
  - Memory leak detection
  - Buffer overflow detection
  - Heap analysis

- **File System Security**
  - Permission analysis
  - Path traversal detection
  - Insecure file operation detection

- **Plugin System Security**
  - Plugin signature verification
  - Unsafe eval detection
  - Plugin sandbox enforcement

- **Network Security**
  - Connection encryption verification
  - Port scanning
  - Protocol security analysis

- **Configuration Security**
  - Weak credential detection
  - CSRF protection validation
  - Debug mode detection

## Quick Start

```bash
# Install the scanner
npm install -g mcp-security-scanner

# Run a scan
mcp-scan /path/to/your/project
```

## Usage

The scanner can be used in three ways:

1. **Command Line Interface**
   ```bash
   mcp-scan [options] <path>
   ```

2. **Programmatic Usage**
   ```javascript
   import { SecurityScanner } from 'mcp-security-scanner';
   const scanner = new SecurityScanner();
   const results = await scanner.scanForVulnerabilities(context);
   ```

3. **WebSocket Server**
   ```javascript
   import { MCPSecurityServer } from 'mcp-security-scanner';
   const server = new MCPSecurityServer();
   server.start();
   ```

## Configuration

Create a `scanner.config.json` file:

```json
{
  "excludePaths": [".git", "node_modules"],
  "maxDepth": 5,
  "timeout": 30000,
  "memoryThreshold": 104857600
}
```

## Documentation

- [Installation Guide](./docs/installation.html)
- [API Reference](./docs/api-reference.html)
- [Configuration Options](./docs/configuration.html)
- [Security Checks](./docs/security-checks.html)

## Contributing

Contributions are welcome! Please read our [Contributing Guide](./CONTRIBUTING.html) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE.html) file for details.