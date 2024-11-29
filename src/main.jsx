// MCP Security Scanner
// A comprehensive security scanner implementing Model Context Protocol

import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import crypto from 'crypto';
import fs from 'fs/promises';
import path from 'path';

class SecurityScanner {
    constructor() {
        // Initialize vulnerability database
        this.vulnerabilityDB = {
            memoryLeaks: new Set(),
            insecureFileOperations: new Set(),
            unsafePluginLoads: new Set(),
            commandInjection: new Set(),
            insecureConnections: new Set()
        };
        
        // Scanning configurations
        this.scanConfig = {
            maxDepth: 5,
            timeout: 30000,
            excludedPaths: new Set(['.git', 'node_modules']),
            memoryThreshold: 1024 * 1024 * 100 // 100MB
        };
    }

    async scanForVulnerabilities(context) {
        const results = {
            vulnerabilities: [],
            timestamp: new Date().toISOString(),
            scanDuration: 0
        };

        const startTime = Date.now();

        try {
            // Memory vulnerability scanning
            await this.scanMemoryVulnerabilities(context, results);
            
            // File system vulnerability scanning
            await this.scanFileSystemVulnerabilities(context, results);
            
            // Plugin system vulnerability scanning
            await this.scanPluginSystemVulnerabilities(context, results);
            
            // Network security scanning
            await this.scanNetworkSecurity(context, results);
            
            // Configuration vulnerability scanning
            await this.scanConfigurationVulnerabilities(context, results);

            results.scanDuration = Date.now() - startTime;
            return results;

        } catch (error) {
            results.error = {
                message: error.message,
                stack: error.stack
            };
            return results;
        }
    }

    async scanMemoryVulnerabilities(context, results) {
        // Check for memory leaks
        const memoryUsage = process.memoryUsage();
        if (memoryUsage.heapUsed > this.scanConfig.memoryThreshold) {
            results.vulnerabilities.push({
                type: 'MEMORY_LEAK',
                severity: 'HIGH',
                details: `High memory usage detected: ${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`,
                location: 'process',
                recommendation: 'Implement proper memory management and garbage collection'
            });
        }

        // Check for buffer overflows
        if (context.bufferSize && context.bufferSize > 2048) {
            results.vulnerabilities.push({
                type: 'BUFFER_OVERFLOW',
                severity: 'CRITICAL',
                details: 'Potential buffer overflow detected',
                location: context.bufferLocation || 'unknown',
                recommendation: 'Implement proper buffer size checks'
            });
        }
    }

    async scanFileSystemVulnerabilities(context, results) {
        // Check for insecure file permissions
        const filePermissions = await this.checkFilePermissions(context.basePath);
        for (const [file, perms] of Object.entries(filePermissions)) {
            if (perms.mode & 0o777 === 0o777) {
                results.vulnerabilities.push({
                    type: 'INSECURE_FILE_PERMISSIONS',
                    severity: 'HIGH',
                    details: `File has overly permissive access: ${file}`,
                    location: file,
                    recommendation: 'Restrict file permissions to minimum required'
                });
            }
        }

        // Check for path traversal vulnerabilities
        if (context.paths) {
            for (const path of context.paths) {
                if (path.includes('..') || path.includes('../')) {
                    results.vulnerabilities.push({
                        type: 'PATH_TRAVERSAL',
                        severity: 'CRITICAL',
                        details: 'Potential path traversal vulnerability detected',
                        location: path,
                        recommendation: 'Sanitize and validate all file paths'
                    });
                }
            }
        }
    }

    async scanPluginSystemVulnerabilities(context, results) {
        // Check for unsafe plugin loading
        if (context.plugins) {
            for (const plugin of context.plugins) {
                // Verify plugin signature
                const isValidSignature = await this.verifyPluginSignature(plugin);
                if (!isValidSignature) {
                    results.vulnerabilities.push({
                        type: 'UNSIGNED_PLUGIN',
                        severity: 'HIGH',
                        details: `Plugin ${plugin.name} is not properly signed`,
                        location: plugin.path,
                        recommendation: 'Implement plugin signing and verification'
                    });
                }

                // Check for unsafe eval usage
                if (plugin.code && plugin.code.includes('eval(')) {
                    results.vulnerabilities.push({
                        type: 'UNSAFE_EVAL',
                        severity: 'CRITICAL',
                        details: `Plugin ${plugin.name} uses unsafe eval()`,
                        location: plugin.path,
                        recommendation: 'Avoid using eval() in plugins'
                    });
                }
            }
        }
    }

    async scanNetworkSecurity(context, results) {
        // Check for insecure connections
        if (context.connections) {
            for (const conn of context.connections) {
                if (!conn.encrypted || conn.protocol === 'http:') {
                    results.vulnerabilities.push({
                        type: 'INSECURE_CONNECTION',
                        severity: 'HIGH',
                        details: 'Unencrypted connection detected',
                        location: `${conn.host}:${conn.port}`,
                        recommendation: 'Use HTTPS/TLS for all connections'
                    });
                }
            }
        }

        // Check for open ports
        const openPorts = await this.scanOpenPorts(context.host);
        for (const port of openPorts) {
            if (!context.allowedPorts?.includes(port)) {
                results.vulnerabilities.push({
                    type: 'OPEN_PORT',
                    severity: 'MEDIUM',
                    details: `Potentially unnecessary open port: ${port}`,
                    location: `${context.host}:${port}`,
                    recommendation: 'Close unnecessary ports'
                });
            }
        }
    }

    async scanConfigurationVulnerabilities(context, results) {
        // Check for default/weak credentials
        if (context.credentials) {
            const weakPasswords = ['admin', 'password', '123456', 'default'];
            for (const [user, pass] of Object.entries(context.credentials)) {
                if (weakPasswords.includes(pass.toLowerCase())) {
                    results.vulnerabilities.push({
                        type: 'WEAK_CREDENTIALS',
                        severity: 'HIGH',
                        details: `Weak password detected for user: ${user}`,
                        location: 'authentication',
                        recommendation: 'Implement strong password requirements'
                    });
                }
            }
        }

        // Check for insecure configurations
        if (context.config) {
            if (context.config.debug === true) {
                results.vulnerabilities.push({
                    type: 'DEBUG_MODE',
                    severity: 'MEDIUM',
                    details: 'Debug mode is enabled in production',
                    location: 'configuration',
                    recommendation: 'Disable debug mode in production'
                });
            }

            if (!context.config.csrfProtection) {
                results.vulnerabilities.push({
                    type: 'MISSING_CSRF',
                    severity: 'HIGH',
                    details: 'CSRF protection is not enabled',
                    location: 'configuration',
                    recommendation: 'Enable CSRF protection'
                });
            }
        }
    }

    // Utility methods
    async verifyPluginSignature(plugin) {
        try {
            if (!plugin.signature || !plugin.publicKey) {
                return false;
            }

            const verify = crypto.createVerify('SHA256');
            verify.update(plugin.code);
            return verify.verify(plugin.publicKey, plugin.signature);
        } catch (error) {
            return false;
        }
    }

    async scanOpenPorts(host) {
        // Implementation for port scanning
        // Note: This is a simplified version
        return new Promise((resolve) => {
            const openPorts = [];
            // Add actual port scanning logic here
            resolve(openPorts);
        });
    }

    async checkFilePermissions(basePath) {
        const results = {};
        try {
            const files = await fs.readdir(basePath);
            for (const file of files) {
                const fullPath = path.join(basePath, file);
                const stats = await fs.stat(fullPath);
                results[fullPath] = {
                    mode: stats.mode,
                    uid: stats.uid,
                    gid: stats.gid
                };
            }
        } catch (error) {
            console.error('Error checking file permissions:', error);
        }
        return results;
    }
}

class MCPSecurityServer {
    constructor(port = 3000) {
        this.port = port;
        this.scanner = new SecurityScanner();
        this.server = createServer();
        this.wss = new WebSocketServer({ server: this.server });
        this.setupWebSocket();
    }

    setupWebSocket() {
        this.wss.on('connection', (ws) => {
            console.log('Client connected');

            ws.on('message', async (message) => {
                try {
                    const request = JSON.parse(message);
                    
                    if (request.type === 'scan') {
                        const results = await this.scanner.scanForVulnerabilities(request.context);
                        ws.send(JSON.stringify({
                            type: 'scanResults',
                            data: results
                        }));
                    }
                } catch (error) {
                    ws.send(JSON.stringify({
                        type: 'error',
                        error: {
                            message: error.message,
                            stack: error.stack
                        }
                    }));
                }
            });

            ws.on('close', () => {
                console.log('Client disconnected');
            });
        });
    }

    start() {
        this.server.listen(this.port, () => {
            console.log(`MCP Security Scanner server running on port ${this.port}`);
        });
    }

    stop() {
        this.server.close();
    }
}

// Export the server
export { MCPSecurityServer, SecurityScanner };

// Start the server if this is the main module
if (import.meta.url === new URL(import.meta.url).href) {
    const server = new MCPSecurityServer();
    server.start();
}
