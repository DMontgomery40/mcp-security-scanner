FROM node:20-slim

WORKDIR /app

COPY package*.json ./
COPY tsconfig.json ./

RUN npm ci

COPY src ./src

RUN npm run build && chmod +x dist/index.js

RUN useradd -m -s /bin/bash scanner && \
    chown -R scanner:scanner /app

USER scanner

ENV NODE_ENV=production
ENV MCP_TRANSPORT=stdio
ENV MCP_SERVER_HOST=0.0.0.0
ENV MCP_SERVER_PORT=8100

EXPOSE 8100

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD if [ "$MCP_TRANSPORT" = "http" ]; then \
    curl -sf http://localhost:${MCP_SERVER_PORT}/health || exit 1; \
  else exit 0; fi

CMD ["node", "dist/index.js"]
