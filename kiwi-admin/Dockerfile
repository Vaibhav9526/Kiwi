# kiwi-admin service image (T-131; ADR-007).
#
# Multi-stage: builder runs the type gate and emits dist/; runner ships
# production deps + dist only. No secrets baked in — DATABASE_URL arrives
# at runtime via compose env.
#
# NOTE (T-130): the runtime entrypoint `dist/server.js` (with GET /healthz)
# lands with the Drizzle/service work. Until then `docker compose up admin`
# builds green but the container exits non-zero — expected, tracked in
# infra/README.md. The type gate below still verifies every build.

FROM node:22-bookworm-slim AS builder
WORKDIR /app
COPY package.json package-lock.json ./
# NOTE: `npm install` (not `ci`) — the repo lock is currently drifted
# (@types/node peer resolution) so strict `ci` fails even though the tree
# installs and tests green. Agent 5 regenerates the lock under T-130
# (`npm install` locally); then this restores `npm ci` for full pinning.
RUN npm install
COPY tsconfig.json vitest.config.ts ./
COPY src/ ./src/
COPY tests/ ./tests/
# Type gate: the image must not build unless types are clean.
RUN npm run typecheck
# tsconfig sets noEmit for editors; emit explicitly for the image.
RUN npx tsc -p tsconfig.json --noEmit false --outDir dist

FROM node:22-bookworm-slim AS runner
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
# NOTE: full node_modules (incl. devDeps) is carried over because
# `npm ci --omit=dev` fails on the current lock drift (@types/node peer
# resolution; repo lock is stale — Agent 5 regenerates it under T-130 with
# `npm install`, then this restores pruning). Keeps the image honest today.
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
EXPOSE 3001
# node:22 has global fetch: healthcheck needs no curl in the image.
HEALTHCHECK --interval=10s --timeout=5s --retries=6 --start-period=60s \
  CMD node -e "fetch('http://localhost:3001/healthz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "dist/server.js"]
