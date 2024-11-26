import React, { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Loader2, AlertTriangle, CheckCircle } from 'lucide-react';

const SecurityScanner = () => {
  const [scanStatus, setScanStatus] = useState('idle');
  const [findings, setFindings] = useState([]);

  const startScan = async () => {
    setScanStatus('scanning');
    // Scanning logic will go here
    setTimeout(() => {
      setScanStatus('complete');
    }, 2000);
  };

  return (
    <div className="w-full max-w-4xl mx-auto p-4">
      <Card>
        <CardHeader>
          <CardTitle>MCP Security Scanner</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <Button 
              onClick={startScan}
              disabled={scanStatus === 'scanning'}
              className="w-full"
            >
              {scanStatus === 'scanning' ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Scanning...
                </>
              ) : 'Start Security Scan'}
            </Button>

            {scanStatus === 'complete' && (
              <Alert>
                <CheckCircle className="h-4 w-4 mr-2" />
                <AlertDescription>
                  Scan complete!
                </AlertDescription>
              </Alert>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default SecurityScanner;