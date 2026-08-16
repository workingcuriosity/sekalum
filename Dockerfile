FROM node:20-alpine

ARG APP_VERSION=1.0.0-beta.1

LABEL org.opencontainers.image.title="Sekalum" \
  org.opencontainers.image.description="Open Source credential lifecycle management platform." \
  org.opencontainers.image.licenses="AGPL-3.0-only" \
  org.opencontainers.image.source="https://github.com/workingcuriosity/sekalum" \
  org.opencontainers.image.version="${APP_VERSION}"

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY src ./src
COPY public ./public
COPY LICENSE NOTICE SECURITY.md ./
COPY docs/project/THIRD_PARTY_SOFTWARE.md ./docs/project/

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD ["node", "-e", "const http=require('node:http'); const port=process.env.OAUTH_CALLBACK_PORT || 3000; const basePath=(process.env.BASE_PATH || '/').replace(/\\/$/, '') || ''; const request=http.get({host:'127.0.0.1', port, path:`${basePath}/health`}, (response) => { process.exit(response.statusCode === 200 ? 0 : 1); }); request.on('error', () => process.exit(1)); request.setTimeout(4000, () => { request.destroy(); process.exit(1); });"]

CMD ["node", "src/index.js"]
