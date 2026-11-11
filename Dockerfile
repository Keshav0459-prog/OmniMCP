# ==============================================================================
# OmniMCP — Production Multi-stage Container Dockerfile
# Optimized for Node.js 22 (built-in SQLite), least-privilege, and small footprint
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Dependency & Compilation Stage
# ------------------------------------------------------------------------------
FROM node:22-alpine AS builder

WORKDIR /app

# Install build dependencies
COPY package*.json tsconfig.json ./
RUN npm ci

# Copy source code and frontend assets
COPY src/ ./src/
COPY public/ ./public/

# Compile TypeScript to JavaScript in /app/dist
RUN npm run build

# ------------------------------------------------------------------------------
# Stage 2: Minimal Production Runtime Stage
# ------------------------------------------------------------------------------
FROM node:22-alpine AS runner

WORKDIR /app

# Production environment variables
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    NO_BROWSER_OPEN=true \
    SQLITE_DB_PATH=/app/data/omnimcp.db

# Install production dependencies only (keep devDependencies out of final image)
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy built artifacts and static web frontend
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/public ./public

# Create persistent data directory and grant non-root ownership to built-in 'node' user
RUN mkdir -p /app/data && chown -R node:node /app

# Security: Execute as non-root user (UID 1000)
USER node

# Expose HTTP dashboard and gateway port
EXPOSE 3000

# Container liveness check using lightweight unauthenticated /health probe on dynamic $PORT
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:' + (process.env.PORT || 3000) + '/health', (r) => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

# Start OmniMCP HTTP Dashboard & API Gateway
CMD ["node", "dist/index.js", "--http"]
