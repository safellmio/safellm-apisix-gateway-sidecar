# SafeLLM APISIX Gateway Sidecar (OSS)

SafeLLM is an AI security sidecar for Apache APISIX.  
It scans prompts before they reach your model and provides layered protections with low latency.

## What's Included

- L1 keyword blocking (FlashText)
- L1.5 PII detection (Presidio regex)
- Redis cache support (optional)
- Prometheus metrics endpoint (`/metrics`)
- APISIX `/auth` integration + direct `/v1/guard` API

## Image Tags

- `safellm/safellm-apisix-gateway-sidecar:2.2.0` (recommended, immutable release)
- `safellm/safellm-apisix-gateway-sidecar:2.1`
- `safellm/safellm-apisix-gateway-sidecar:2`

Current 2.2.0 manifest digest:
- `TBD after publish`

## Quick Run (No Redis)

```bash
docker pull safellm/safellm-apisix-gateway-sidecar:2.2.0
docker run --rm -p 8000:8000 \
  -e ENABLE_CACHE=false \
  -e SHADOW_MODE=false \
  safellm/safellm-apisix-gateway-sidecar:2.2.0
```

Then test:

```bash
curl -i http://localhost:8000/health
curl -i -X POST http://localhost:8000/v1/guard \
  -H 'Content-Type: application/json' \
  -d '{"text":"hello world"}'
```

## Run Full OSS Stack (Recommended)

Use Docker Compose + APISIX + Redis:

1. `git clone https://github.com/safellmio/safellm-apisix-gateway-sidecar.git`
2. `cd safellm-apisix-gateway-sidecar/safellm-oss`
3. `docker compose up -d --build`

## Kubernetes

Deploy with Helm chart (production path):

- Docs: https://safellm.io/docs/intro/kubernetes
- Chart: `safellm/safellm-oss`

## Notes

- Default OSS mode is `SHADOW_MODE=true` (log-only for suspicious prompts).
- For strict blocking, set `SHADOW_MODE=false`.
- For production, pin exact version or digest and avoid mutable tags.
