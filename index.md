# MCP Security Scanner

## 🔒 Overview
A security vulnerability scanner that helps identify potential security issues in plugin code.

## Features
- Scan local JavaScript/TypeScript files
- Scan GitHub repositories
- Detect common security vulnerabilities:
  - Unsafe eval() usage
  - Path traversal vulnerabilities
  - Dangerous module imports

## Usage
1. Visit our [web interface](https://dmontgomery40.github.io/mcp-security-scanner)
2. Either:
   - Enter a GitHub repository URL to scan
   - Upload local files for scanning

## Running Locally
```bash
git clone https://github.com/DMontgomery40/mcp-security-scanner
cd mcp-security-scanner
npm install
npm run dev
```

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.