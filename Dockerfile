# syntax=docker/dockerfile:1
FROM node:22-alpine AS base
RUN apk add --no-cache libc6-compat
WORKDIR /app

FROM base AS deps
COPY package.json package-lock.json ./
COPY packages ./packages
COPY examples ./examples
RUN npm ci

FROM base AS build
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app ./
COPY . .
RUN npm run build
# Bundle the migration script (drizzle + postgres + zod inlined) so the runtime image needs no node_modules or tsx.
RUN npx esbuild scripts/migrate.ts --bundle --platform=node --format=esm --target=node22 \
    --banner:js="import{createRequire as __cr}from'module';const require=__cr(import.meta.url);" \
    --outfile=migrate.mjs

FROM base AS runner
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 HOSTNAME=0.0.0.0 PORT=8080
RUN addgroup -S -g 1001 app && adduser -S -u 1001 -G app app
COPY --from=build --chown=app:app /app/.next/standalone ./
COPY --from=build --chown=app:app /app/.next/static ./.next/static
COPY --from=build --chown=app:app /app/public ./public
COPY --from=build --chown=app:app /app/content ./content
COPY --from=build --chown=app:app /app/drizzle ./drizzle
COPY --from=build --chown=app:app /app/migrate.mjs ./migrate.mjs
USER app
EXPOSE 8080
# Migrations: `node migrate.mjs` (used by the PRE_DEPLOY job).
CMD ["node", "server.js"]
