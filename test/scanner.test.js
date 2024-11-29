import { SecurityScanner } from '../main.js';

describe('SecurityScanner', () => {
  let scanner;

  beforeEach(() => {
    scanner = new SecurityScanner();
  });

  test('scanner initializes with default configuration', () => {
    expect(scanner.scanConfig).toBeDefined();
    expect(scanner.scanConfig.maxDepth).toBe(5);
    expect(scanner.scanConfig.timeout).toBe(30000);
  });

  test('vulnerabilityDB is initialized', () => {
    expect(scanner.vulnerabilityDB).toBeDefined();
    expect(scanner.vulnerabilityDB.memoryLeaks).toBeDefined();
    expect(scanner.vulnerabilityDB.insecureFileOperations).toBeDefined();
  });
});