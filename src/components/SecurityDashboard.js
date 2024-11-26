import React, { useState, useEffect } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Shield, AlertTriangle, Check, ChevronDown, ChevronRight } from 'lucide-react';

const SecurityAuditDashboard = () => {
  const [expandedFindings, setExpandedFindings] = useState(new Set());
  const [activePlugin, setActivePlugin] = useState('all');
  
  const findings = [
    {
      id: 1,
      plugin: 'filesystem',
      severity: 'high',
      title: 'Path Traversal via TOCTOU Race Condition',
      description: 'Path validation in filesystem plugin vulnerable to Time-of-Check-Time-of-Use race conditions',
      location: 'src/filesystem/index.ts:validatePath()',
      impact: 'Potential unauthorized file access outside allowed directories',
      recommendation: `
        1. Implement atomic operations using file handles
        2. Maintain file control between validation and operations
        3. Add additional runtime path validation
        4. Consider chroot-like directory restrictions
      `,
      proofOfConcept: `
        // Current Vulnerable Pattern
        const validPath = await validatePath(filePath);
        // Race condition window here
        await fs.readFile(validPath, "utf-8");
      `
    },
    {
      id: 2,
      plugin: 'memory',
      severity: 'high',
      title: 'Arbitrary File Write in Memory Plugin',
      description: 'Memory plugin stores data in unvalidated file paths without proper permissions checks',
      location: 'src/memory/index.ts:MEMORY_FILE_PATH',
      impact: 'Potential file system access outside intended directories',
      recommendation: `
        1. Validate and restrict memory file storage location
        2. Implement proper file permissions
        3. Add sanitization for stored data
        4. Consider using a secure database instead of file storage
      `,
      proofOfConcept: `
        const MEMORY_FILE_PATH = path.join(__dirname, 'memory.json');
        // No validation of storage location
        await fs.writeFile(MEMORY_FILE_PATH, data);
      `
    },
    {
      id: 3,
      plugin: 'filesystem',
      severity: 'medium',
      title: 'Insufficient Input Sanitization',
      description: 'File operations lack comprehensive input validation and sanitization',
      location: 'src/filesystem/index.ts:multiple functions',
      impact: 'Potential for injection attacks via malicious filenames or content',
      recommendation: `
        1. Implement strict input validation for all file operations
        2. Sanitize file names and paths
        3. Add content-type validation where appropriate
        4. Implement maximum path length restrictions
      `,
      proofOfConcept: `
        // Current implementation lacks thorough validation
        const results = await searchFiles(validPath, parsed.data.pattern);
      `
    },
    {
      id: 4,
      plugin: 'memory',
      severity: 'medium',
      title: 'JSON Injection Vulnerability',
      description: 'Memory plugin stores data without proper JSON encoding/sanitization',
      location: 'src/memory/index.ts:saveGraph()',
      impact: 'Potential for JSON injection attacks and data corruption',
      recommendation: `
        1. Implement JSON sanitization
        2. Add schema validation for stored data
        3. Use secure serialization methods
        4. Add data integrity checks
      `,
      proofOfConcept: `
        // Vulnerable to JSON injection
        const lines = graph.entities.map(e => JSON.stringify({ type: "entity", ...e }));
      `
    },
    {
      id: 5,
      plugin: 'filesystem',
      severity: 'low',
      title: 'Error Message Information Disclosure',
      description: 'Detailed error messages could reveal sensitive system information',
      location: 'src/filesystem/index.ts:error handling',
      impact: 'Information disclosure about file system structure and paths',
      recommendation: `
        1. Implement generic error messages
        2. Log detailed errors server-side only
        3. Add error standardization
        4. Implement proper error categorization
      `,
      proofOfConcept: `
        throw new Error(\`Access denied - path outside allowed directories: \${absolute}\`);
      `
    }
  ];

  const toggleFinding = (id) => {
    const newExpanded = new Set(expandedFindings);
    if (newExpanded.has(id)) {
      newExpanded.delete(id);
    } else {
      newExpanded.add(id);
    }
    setExpandedFindings(newExpanded);
  };

  const filteredFindings = activePlugin === 'all' 
    ? findings
    : findings.filter(f => f.plugin === activePlugin);

  const getSeverityColor = (severity) => {
    switch(severity) {
      case 'high':
        return 'bg-red-100 text-red-800';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800';
      case 'low':
        return 'bg-blue-100 text-blue-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto p-4 space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="h-6 w-6"/>
              <CardTitle>MCP Security Audit Dashboard</CardTitle>
            </div>
            <div className="flex gap-2">
              <button 
                className={`px-3 py-1 rounded ${activePlugin === 'all' ? 'bg-blue-500 text-white' : 'bg-gray-100'}`}
                onClick={() => setActivePlugin('all')}
              >
                All
              </button>
              <button 
                className={`px-3 py-1 rounded ${activePlugin === 'filesystem' ? 'bg-blue-500 text-white' : 'bg-gray-100'}`}
                onClick={() => setActivePlugin('filesystem')}
              >
                Filesystem
              </button>
              <button 
                className={`px-3 py-1 rounded ${activePlugin === 'memory' ? 'bg-blue-500 text-white' : 'bg-gray-100'}`}
                onClick={() => setActivePlugin('memory')}
              >
                Memory
              </button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-3 gap-4 mb-6">
            <Card>
              <CardContent className="pt-4">
                <div className="text-2xl font-bold text-red-600">
                  {filteredFindings.filter(f => f.severity === 'high').length}
                </div>
                <div className="text-sm text-gray-600">High Severity</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4">
                <div className="text-2xl font-bold text-yellow-600">
                  {filteredFindings.filter(f => f.severity === 'medium').length}
                </div>
                <div className="text-sm text-gray-600">Medium Severity</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4">
                <div className="text-2xl font-bold text-blue-600">
                  {filteredFindings.filter(f => f.severity === 'low').length}
                </div>
                <div className="text-sm text-gray-600">Low Severity</div>
              </CardContent>
            </Card>
          </div>

          <div className="space-y-4">
            {filteredFindings.map(finding => (
              <Card key={finding.id} className="overflow-hidden">
                <div 
                  className="p-4 cursor-pointer hover:bg-gray-50"
                  onClick={() => toggleFinding(finding.id)}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {expandedFindings.has(finding.id) ? (
                        <ChevronDown className="h-4 w-4" />
                      ) : (
                        <ChevronRight className="h-4 w-4" />
                      )}
                      <span className={`px-2 py-1 rounded-full text-xs font-semibold ${getSeverityColor(finding.severity)}`}>
                        {finding.severity.toUpperCase()}
                      </span>
                      <h3 className="font-semibold">{finding.title}</h3>
                    </div>
                    <span className="text-sm text-gray-500">{finding.plugin}</span>
                  </div>
                </div>
                
                {expandedFindings.has(finding.id) && (
                  <div className="px-4 pb-4 pt-2 border-t">
                    <div className="space-y-4">
                      <div>
                        <h4 className="font-semibold text-sm text-gray-600">Description</h4>
                        <p className="mt-1">{finding.description}</p>
                      </div>
                      
                      <div>
                        <h4 className="font-semibold text-sm text-gray-600">Location</h4>
                        <p className="mt-1 font-mono text-sm bg-gray-50 p-2 rounded">
                          {finding.location}
                        </p>
                      </div>
                      
                      <div>
                        <h4 className="font-semibold text-sm text-gray-600">Impact</h4>
                        <p className="mt-1">{finding.impact}</p>
                      </div>
                      
                      <div>
                        <h4 className="font-semibold text-sm text-gray-600">Proof of Concept</h4>
                        <pre className="mt-1 font-mono text-sm bg-gray-50 p-2 rounded overflow-x-auto">
                          {finding.proofOfConcept}
                        </pre>
                      </div>
                      
                      <div>
                        <h4 className="font-semibold text-sm text-gray-600">Recommendations</h4>
                        <div className="mt-1 space-y-2">
                          {finding.recommendation.split('\n').map((rec, i) => (
                            <div key={i} className="flex items-start gap-2">
                              <Check className="h-4 w-4 mt-1 text-green-500"/>
                              <p className="text-sm">{rec.trim()}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </Card>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default SecurityAuditDashboard;
