# APISIX Reference Deployment (SafeLLM OSS)

This folder provides a minimal APISIX + SafeLLM sidecar setup for users who do not already run APISIX.

The goal is quick validation:
- APISIX as gateway
- SafeLLM as request security layer
- Redis as cache backend
- Upstream mock service (`httpbin`)

## Who This Is For

- You want to try prompt/PII filtering in front of an API in under 10 minutes.
- You are evaluating APISIX integration and need a working baseline.
- You want a reproducible demo stack for presales and technical discovery calls.

## Quick Start

```bash
cd safellm-oss/examples/apisix-reference
cp .env.example .env
docker compose up -d
```

Wait for health:

```bash
docker compose ps
```

Run smoke tests:

```bash
bash smoke-test.sh
```

## Endpoints

- `GET /health` -> sidecar health via APISIX
- `POST /v1/guard` -> direct sidecar decision via APISIX route
- `POST /api/*` -> protected upstream traffic (APISIX pre-check + proxy)
- `GET /direct/*` -> upstream bypass (for comparison only)

Default URL:
- `http://127.0.0.1:19080`

## Shadow vs Block Mode

Default:
- `SHADOW_MODE=true` in `.env`
- Suspicious traffic is logged as would-block, but still allowed.

To enforce blocking:

1. Set `SHADOW_MODE=false` in `.env`
2. Restart:
   ```bash
   docker compose up -d --force-recreate
   ```

## Main Tuning Knobs

- `SAFELLM_TIMEOUT_MS`: timeout for APISIX -> sidecar call.
- `SAFELLM_MAX_BODY_SIZE`: max scanned request body.
- `SAFELLM_FAIL_OPEN`: behavior when sidecar is unavailable.
  - `false` (default): fail-closed, safer.
  - `true`: fail-open, higher availability but weaker security.

## Cleanup

```bash
docker compose down -v
```

## Production Notes

This deployment is a reference setup, not a complete production architecture.

Before production, add:
- TLS termination and certificate management
- authenticated APISIX admin plane
- externalized secrets
- persistent metrics and logs
- explicit SLO/timeout/retry policy
- HA strategy (gateway + sidecar replicas, Redis HA if required)
