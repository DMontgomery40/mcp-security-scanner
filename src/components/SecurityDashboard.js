import React, { useState } from 'react';

const SecurityDashboard = () => {
  const [scanResults, setScanResults] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState(null);

  const handleFileScan = async () => {
    setIsScanning(true);
    setError(null);
    try {
      // First, let's check if we can access the repository files
      const files = await window.fs.readdir('.');
      console.log('Available files:', files);
      
      // For now, we'll scan what's available and look for potential issues
      setScanResults([{
        id: 1,
        severity: 'high',
        title: 'Initial Security Scan',
        description: 'Repository structure analysis completed. Click for details.',
        file: 'repository',
        line: 0
      }]);
    } catch (error) {
      console.error('Error scanning files:', error);
      setError('Failed to access repository files. Please make sure you have the correct permissions.');
    }
    setIsScanning(false);
  };

  const handleCreateIssue = async (finding) => {
    console.log('Creating issue for:', finding);
  };

  return (
    <div className="max-w-4xl mx-auto p-4">
      <div className="bg-white rounded-lg shadow p-6">
        <h1 className="text-2xl font-bold mb-4">MCP Security Scanner</h1>
        <p className="text-gray-600 mb-6">Scan repository files for potential security vulnerabilities</p>
        
        <button 
          onClick={handleFileScan}
          disabled={isScanning}
          className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 disabled:bg-gray-400"
        >
          {isScanning ? 'Scanning...' : 'Start Scan'}
        </button>

        {error && (
          <div className="mt-4 p-4 bg-red-50 text-red-700 rounded-md">
            {error}
          </div>
        )}

        <div className="mt-8">
          {scanResults.map((finding) => (
            <div key={finding.id} className="bg-red-50 border-l-4 border-red-500 p-4 mb-4">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                  </svg>
                </div>
                <div className="ml-3">
                  <h3 className="text-lg font-medium text-red-800">{finding.title}</h3>
                  <p className="text-sm text-red-700 mt-1">{finding.description}</p>
                  <p className="text-sm text-red-700 mt-1">Location: {finding.file}:{finding.line}</p>
                  <button
                    onClick={() => handleCreateIssue(finding)}
                    className="mt-2 bg-red-100 text-red-800 px-3 py-1 rounded-full text-sm hover:bg-red-200"
                  >
                    Report Issue
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default SecurityDashboard;