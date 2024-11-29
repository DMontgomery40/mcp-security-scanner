#!/usr/bin/env node

import { SecurityScannerClient } from './client.js';
import path from 'path';

const HELP_TEXT = `
MCP Security Scanner CLI

Usage:
  mcp-scan [options] <path>

Options:
  --help, -h     Show this help message
  --port, -p     Server port (default: 3000)
  --host         Server host (default: localhost)
  --config, -c   Path to config file
  --json         Output results in JSON format
  --quiet, -q    Minimal output
  
Examples:
  mcp-scan /path/to/project
  mcp-scan --port 3001 /path/to/project
  mcp-scan --json /path/to/project > results.json
`;

async function main() {
    const args = process.argv.slice(2);
    
    // Parse arguments
    const options = {
        port: 3000,
        host: 'localhost',
        json: false,
        quiet: false,
        path: null,
        config: null
    };

    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        
        if (arg === '--help' || arg === '-h') {
            console.log(HELP_TEXT);
            process.exit(0);
        } else if (arg === '--port' || arg === '-p') {
            options.port = parseInt(args[++i], 10);
        } else if (arg === '--host') {
            options.host = args[++i];
        } else if (arg === '--json') {
            options.json = true;
        } else if (arg === '--quiet' || arg === '-q') {
            options.quiet = true;
        } else if (arg === '--config' || arg === '-c') {
            options.config = args[++i];
        } else if (!arg.startsWith('-')) {
            options.path = arg;
        }
    }

    if (!options.path) {
        console.error('Error: No path specified');
        console.log(HELP_TEXT);
        process.exit(1);
    }

    // Resolve absolute path
    const scanPath = path.resolve(options.path);

    try {
        // Connect to the scanner server
        const client = new SecurityScannerClient(`ws://${options.host}:${options.port}`);
        
        if (!options.quiet) {
            console.log('Connecting to scanner server...');
        }
        
        await client.connect();

        if (!options.quiet) {
            console.log('Starting security scan...');
        }

        // Prepare scan context
        const context = {
            basePath: scanPath
        };

        // Run the scan
        const results = await client.scanSystem(context);

        // Output results
        if (options.json) {
            console.log(JSON.stringify(results, null, 2));
        } else {
            console.log(client.formatResults(results));
        }

        // Disconnect and exit
        await client.disconnect();
        process.exit(results.vulnerabilities.length > 0 ? 1 : 0);

    } catch (error) {
        console.error('Error:', error.message);
        process.exit(1);
    }
}

main();