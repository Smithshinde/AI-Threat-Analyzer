FROM node:20-alpine AS base
WORKDIR /app

# Dependencies
FROM base AS deps
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Runtime
FROM base AS runtime
RUN addgroup --system --gid 1001 nodejs \
 && adduser  --system --uid 1001 nodejs

COPY --from=deps --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --chown=nodejs:nodejs . .

USER nodejs
EXPOSE 4000
ENV NODE_ENV=production
CMD ["node", "server.js"]
