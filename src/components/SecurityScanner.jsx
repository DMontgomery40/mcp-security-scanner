import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle } from 'lucide-react';

const SecurityScanner = () => {
  const [scanResults, setScanResults] = useState({
    vulnerabilities: [],
    scanning: false,
    error: null
  });

  const analyzePlugin = async (pluginCode) => {
    const vulnerabilities = [];
    
    // Check for unsafe eval usage
    if (pluginCode.includes('eval(')) {
      vulnerabilities.push({
        severity: 'high',
        type: 'unsafe-eval',
        description: 'Usage of eval() can lead to code injection vulnerabilities',
        line: pluginCode.split('\n').findIndex(line => line.includes('eval('))
      });
    }

    // Check for unsafe file system operations
    if (pluginCode.match(/fs\.readFile\s*\(\s*['"]\.\./)) {
      vulnerabilities.push({
        severity: 'high',
        type: 'path-traversal',
        description: 'Potential path traversal vulnerability in file system operations',
        line: pluginCode.split('\n').findIndex(line => line.match(/fs\.readFile\s*\(\s*['"]\.\./))
      });
    }

    return vulnerabilities;
  };

  const startScan = async () => {
    setScanResults(prev => ({ ...prev, scanning: true, error: null }));
    try {
      const vulnerabilities = [];
      setScanResults({
        vulnerabilities,
        scanning: false,
        error: null
      });
    } catch (error) {
      setScanResults(prev => ({
        ...prev,
        scanning: false,
        error: error.message
      }));
    }
  };

  return (
    <div className="max-w-4xl mx-auto p-4">
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center gap-2 mb-4">
          <Shield className="h-6 w-6 text-blue-500" />
          <h1 className="text-2xl font-bold">MCP Security Scanner</h1>
        </div>

        <button 
          onClick={startScan}
          disabled={scanResults.scanning}
          className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 disabled:bg-gray-400"
        >
          {scanResults.scanning ? 'Scanning...' : 'Start Scan'}
        </button>

        {scanResults.error && (
          <div className="mt-4 p-4 bg-red-50 text-red-700 rounded-md flex items-start gap-2">
            <AlertTriangle className="h-5 w-5 mt-0.5" />
            <span>{scanResults.error}</span>
          </div>
        )}

        <div className="mt-6 space-y-4">
          {scanResults.vulnerabilities.map((vuln, index) => (
            <div 
              key={index}
              className={`p-4 rounded-md flex items-start gap-2 ${
                vuln.severity === 'high' ? 'bg-red-50 text-red-700' : 'bg-yellow-50 text-yellow-700'
              }`}
            >
              <AlertTriangle className="h-5 w-5 mt-0.5" />
              <div>
                <h3 className="font-semibold">{vuln.type}</h3>
                <p>{vuln.description}</p>
                <p className="text-sm mt-1 opacity-75">Line: {vuln.line + 1}</p>
              </div>
            </div>
          ))}

          {scanResults.vulnerabilities.length === 0 && !scanResults.scanning && !scanResults.error && (
            <div className="flex items-center gap-2 text-green-600">
              <CheckCircle className="h-5 w-5" />
              <span>No vulnerabilities found</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SecurityScanner;