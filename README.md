# MCP Security Scanner

A security vulnerability scanner built with MCP plugins for analyzing JavaScript code.

## Features

- Scans JavaScript files for common security vulnerabilities
- Monitors memory usage during scanning
- Provides detailed reporting of findings
- Integration with GitHub for issue tracking

## Getting Started

1. Clone the repository
2. Install dependencies: `npm install`
3. Run the development server: `npm run dev`

## Deployment

To deploy to GitHub Pages:

```bash
git checkout -b gh-pages
npm run build
git add dist
git commit -m "Deploy to GitHub Pages"
git push origin gh-pages
```

Then enable GitHub Pages in your repository settings.
