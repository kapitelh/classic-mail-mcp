FROM node:24-alpine3.24 AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev --ignore-scripts

FROM node:24-alpine3.24
LABEL org.opencontainers.image.source="https://github.com/kapitelh/classic-mail-mcp" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.title="Classic Mail MCP"
ENV NODE_ENV=production HOST=0.0.0.0 SQLITE_PATH=/data/mail.sqlite
WORKDIR /app
# Keep package managers and their dependency trees out of the runtime image.
RUN apk upgrade --no-cache \
    && rm -rf /usr/local/lib/node_modules/npm /opt/yarn-* \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/yarn /usr/local/bin/yarnpkg \
    && mkdir /data && chown node:node /data
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/package.json ./package.json
USER node
EXPOSE 8080
CMD ["node", "dist/server.js"]
