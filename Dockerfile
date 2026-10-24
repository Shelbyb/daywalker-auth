# syntax=docker/dockerfile:1
#
# Production image for Daywalker Auth (Next.js standalone output).
#   docker build -t daywalker-auth .
#   docker run --rm -p 8080:8080 --env-file .env.production daywalker-auth
# Migrations are a separate step with the same image: `docker run ... daywalker-auth node migrate.mjs`
# (App Platform runs it as a PRE_DEPLOY job). Never bake secrets into the image: pass them at run time.
#
# Base image: pin by digest in your own registry mirror if you need byte-for-byte reproducible builds
# (`docker buildx imagetools inspect node:22-alpine`), and rebuild regularly to pick up security patches.

FROM node:22-alpine AS base
RUN apk add --no-cache libc6-compat
WORKDIR /app

# ---- dependencies: only the manifests, so this layer is cached until they change ----
FROM base AS deps
COPY package.json package-lock.json ./
COPY packages/sdk/package.json ./packages/sdk/package.json
COPY packages/cli/package.json ./packages/cli/package.json
COPY examples/nextjs/package.json ./examples/nextjs/package.json
# --ignore-scripts: no dependency gets to run an install script in the build. Native packages
# (argon2, esbuild, swc) ship prebuilt binaries as optional dependencies and don't need one.
RUN npm ci --ignore-scripts

# ---- build ----
FROM base AS build
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/ ./
COPY . .
# `next build` reads no runtime secrets (configuration is validated lazily at start-up).
RUN npm run build
# Bundle the migration script (drizzle + postgres + zod inlined) so the runtime image needs no node_modules or tsx.
RUN npx --no-install esbuild scripts/migrate.ts --bundle --platform=node --format=esm --target=node22 \
    --banner:js="import{createRequire as __cr}from'module';const require=__cr(import.meta.url);" \
    --outfile=migrate.mjs

# ---- runtime ----
FROM node:22-alpine AS runner
LABEL org.opencontainers.image.title="Daywalker Auth" \
      org.opencontainers.image.source="https://github.com/Shelbyb/daywalker-auth"
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 HOSTNAME=0.0.0.0 PORT=8080
WORKDIR /app
# libc6-compat for the native argon2 binding; tini so signals reach Node and zombies are reaped.
# npm, npx and corepack aren't needed at run time, so they are removed (less to patch, less to abuse).
RUN apk add --no-cache libc6-compat tini \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
           /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /opt/yarn-* /usr/local/bin/yarn /usr/local/bin/yarnpkg \
 && addgroup -S -g 1001 app && adduser -S -u 1001 -G app app
# Everything is owned by root and read-only to the app user, except Next's cache directory.
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public
COPY --from=build /app/content ./content
COPY --from=build /app/drizzle ./drizzle
COPY --from=build /app/migrate.mjs ./migrate.mjs
RUN mkdir -p .next/cache && chown app:app .next/cache
USER 1001:1001
EXPOSE 8080
# The shallow check only proves the process answers. (Postgres/Valkey are checked by /healthz?deep=1 for monitors,
# not here, so a database blip doesn't restart healthy containers.)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz',{signal:AbortSignal.timeout(4000)}).then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "server.js"]
