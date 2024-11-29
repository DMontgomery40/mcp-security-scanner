import React, { useState } from 'react';
import { AlertTriangle, CheckCircle2, Shield, Github } from 'lucide-react';

const SecurityScanner = () => {
  const [scanResults, setScanResults] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);
  const [progress, setProgress] = useState({ current: 0, total: 0 });
  const [successMessage, setSuccessMessage] = useState('');
  const [repoUrl, setRepoUrl] = useState('');

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
    if (pluginCode.match(/fs\.readFile\s*\(\s*['"]\.{2}/)) {
      vulnerabilities.push({
        severity: 'high',
        type: 'path-traversal',
        description: 'Potential path traversal vulnerability in file system operations',
        line: pluginCode.split('\n').findIndex(line => line.match(/fs\.readFile\s*\(\s*['"]\.{2}/))
      });
    }

    // Check for dangerous imports
    if (pluginCode.includes('child_process')) {
      vulnerabilities.push({
        severity: 'high',
        type: 'dangerous-import',
        description: 'Usage of child_process module can lead to command injection',
        line: pluginCode.split('\n').findIndex(line => line.includes('child_process'))
      });
    }

    return vulnerabilities;
  };

  const handleFileSelect = async (event) => {
    const files = event.target.files;
    if (!files || files.length === 0) return;

    setScanning(true);
    setError(null);
    setScanResults(null);
    setSuccessMessage('');
    setProgress({ current: 0, total: files.length });

    try {
      let allVulnerabilities = [];

      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        setProgress((prev) => ({ ...prev, current: i + 1 }));

        const content = await file.text();
        const findings = await analyzePlugin(content);
        if (findings.length > 0) {
          allVulnerabilities = [...allVulnerabilities, { file: file.name, findings }];
        }
      }

      if (allVulnerabilities.length === 0) {
        setSuccessMessage(
          `${files.length} file${files.length > 1 ? 's' : ''} scanned. No vulnerabilities found!`
        );
      } else {
        setScanResults(allVulnerabilities);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setScanning(false);
      setProgress({ current: 0, total: 0 });
    }
  };

  const extractRepoInfo = (url) => {
    try {
      const urlObj = new URL(url);
      const pathParts = urlObj.pathname.split('/').filter(Boolean);
      if (pathParts.length < 2) throw new Error('Invalid repository URL');
      return {
        owner: pathParts[0],
        repo: pathParts[1]
      };
    } catch (err) {
      throw new Error('Invalid GitHub repository URL');
    }
  };

  const scanRepo = async () => {
    if (!repoUrl) return;

    setScanning(true);
    setError(null);
    setScanResults(null);
    setSuccessMessage('');

    try {
      const { owner, repo } = extractRepoInfo(repoUrl);

      // Get repository contents
      const files = await getRepoFiles(owner, repo);
      setProgress({ current: 0, total: files.length });

      let allVulnerabilities = [];
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        setProgress((prev) => ({ ...prev, current: i + 1 }));

        // Only scan JavaScript/TypeScript files
        if (!/\.(js|jsx|ts|tsx)$/.test(file.path)) continue;

        const response = await fetch(file.download_url);
        const content = await response.text();
        const findings = await analyzePlugin(content);
        
        if (findings.length > 0) {
          allVulnerabilities = [...allVulnerabilities, { file: file.path, findings }];
        }
      }

      if (allVulnerabilities.length === 0) {
        setSuccessMessage('Repository scanned. No vulnerabilities found!');
      } else {
        setScanResults(allVulnerabilities);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setScanning(false);
      setProgress({ current: 0, total: 0 });
    }
  };

  const getRepoFiles = async (owner, repo) => {
    const response = await fetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/main?recursive=1`);
    const data = await response.json();
    
    if (data.message === 'Not Found') {
      throw new Error('Repository not found or private');
    }
    
    return data.tree.filter(item => item.type === 'blob');
  };

  return (
    <div className="max-w-4xl mx-auto p-6">
      <div className="bg-white rounded-lg shadow-lg p-6">
        <div className="flex items-center gap-3 mb-6">
          <Shield className="h-8 w-8 text-blue-600" />
          <h1 className="text-3xl font-bold text-gray-800">MCP Security Scanner</h1>
        </div>

        {/* GitHub Repository Input */}
        <div className="mb-8">
          <label className="block mb-4">
            <span className="text-gray-700 text-lg flex items-center gap-2">
              <Github className="h-5 w-5" /> Scan GitHub Repository:
            </span>
            <div className="flex gap-2">
              <input
                type="text"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/owner/repo"
                className="flex-1 mt-2 p-2 border border-gray-300 rounded text-gray-700"
              />
              <button
                onClick={scanRepo}
                disabled={scanning || !repoUrl}
                className="mt-2 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed"
              >
                Scan Repo
              </button>
            </div>
          </label>
        </div>

        {/* File Upload */}
        <div className="mb-8">
          <label className="block mb-4">
            <span className="text-gray-700 text-lg">Or Upload Plugin Files:</span>
            <input
              type="file"
              onChange={handleFileSelect}
              multiple
              accept=".js,.jsx,.ts,.tsx"
              className="mt-2 block w-full text-gray-700 bg-gray-100 rounded border border-gray-300 cursor-pointer file:mr-4 file:py-2 file:px-4 file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100"
            />
          </label>
        </div>

        {/* Progress Bar */}
        {scanning && progress.total > 0 && (
          <div className="mb-6">
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div
                className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                style={{ width: `${(progress.current / progress.total) * 100}%` }}
              />
            </div>
            <div className="text-sm text-gray-600 mt-2 text-center">
              {progress.current} of {progress.total} files scanned
            </div>
          </div>
        )}

        {/* Success Message */}
        {successMessage && (
          <div className="mb-6 p-4 bg-green-50 border border-green-200 rounded-lg flex items-center">
            <CheckCircle2 className="h-5 w-5 text-green-600 mr-2" />
            <span className="text-green-800">{successMessage}</span>
          </div>
        )}

        {/* Error Message */}
        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg flex items-center">
            <AlertTriangle className="h-5 w-5 text-red-600 mr-2" />
            <span className="text-red-800">{error}</span>
          </div>
        )}

        {/* Scan Results */}
        {scanResults && (
          <div className="mt-6 space-y-4">
            <h2 className="text-xl font-semibold text-gray-800 mb-4">Scan Results</h2>
            {scanResults.map((result, index) => (
              <div key={index} className="border rounded-lg p-4 bg-gray-50">
                <h3 className="font-semibold text-lg text-gray-800 mb-2">
                  File: {result.file}
                </h3>
                <div className="space-y-3">
                  {result.findings.map((vuln, vIndex) => (
                    <div
                      key={vIndex}
                      className={`p-4 rounded-md ${
                        vuln.severity === 'high'
                          ? 'bg-red-50 text-red-700 border border-red-200'
                          : 'bg-yellow-50 text-yellow-700 border border-yellow-200'
                      }`}
                    >
                      <div className="flex items-start gap-2">
                        <AlertTriangle className="h-5 w-5 mt-0.5 flex-shrink-0" />
                        <div>
                          <h4 className="font-semibold">
                            {vuln.type.charAt(0).toUpperCase() + vuln.type.slice(1)}
                          </h4>
                          <p className="mt-1">{vuln.description}</p>
                          <p className="text-sm mt-1 opacity-75">Line: {vuln.line + 1}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default SecurityScanner;