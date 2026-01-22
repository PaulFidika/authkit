# AuthKit Devserver (Local Issuer + JWT Minting)

This repo includes a **dummy/standalone devserver** that runs AuthKit against Postgres and can mint JWTs for end-to-end testing of downstream services (e.g. `~/doujins-billing`).

## What it provides

- `GET /.well-known/jwks.json` — public keys (JWKS) for JWT verification
- `POST /auth/dev/mint` — **dev-only** endpoint to mint JWTs (guarded by env + shared secret)
- AuthKit API routes under `/auth/*` (mounted for E2E testing AuthKit itself)

## Run with docker-compose

```bash
docker compose -f docker-compose.devserver.yaml up --build
```

This starts:
- Postgres on `localhost:5432`
- AuthKit devserver on `localhost:8080`

Generated dev signing keys are persisted via a docker volume mounted at `/.runtime/authkit`.

## Environment variables

Required:
- `DB_URL` (or `DATABASE_URL`) — Postgres connection string
- `AUTHKIT_ISSUER` — issuer URL embedded in tokens (e.g. `http://issuer:8080` in compose)

Dev minting (optional, but required for billing E2E):
- `AUTHKIT_DEV_MODE=true`
- `AUTHKIT_DEV_MINT_SECRET=...`

## Mint a JWT

```bash
curl -fsS http://localhost:8080/auth/dev/mint \
  -H "Authorization: Bearer change-me" \
  -H "Content-Type: application/json" \
  -d '{"sub":"11111111-1111-1111-1111-111111111111","aud":"billing-app","email":"test@example.com"}'
```

Response:
- `token` — the JWT
- `expires_at` — expiry timestamp

## Use from doujins-billing E2E

Configure billing to trust the issuer:
- `AUTH_ISSUERS='["http://issuer:8080"]'` (from inside compose network)
- `AUTH_EXPECTED_AUDIENCE=billing-app`

Then mint tokens from the issuer and call billing endpoints with:
- `Authorization: Bearer <token>`

## Run AuthKit E2E tests (docker-compose)

These tests spin up `docker-compose.devserver.yaml` and hit the devserver over HTTP:

```bash
go test -tags=e2e ./testing -run DevserverE2E
```
