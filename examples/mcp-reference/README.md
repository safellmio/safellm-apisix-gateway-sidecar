# MCP Reference Deployment (SafeLLM OSS)

This example runs SafeLLM sidecar + Redis and validates both:
- HTTP security API (`/health`, `/v1/guard`)
- MCP stdio tools (`initialize`, `tools/list`, `tools/call`)

It is intended for users who want a quick MCP + security demo using Docker.

## Quick Start

```bash
cd safellm-oss/examples/mcp-reference
cp .env.example .env
docker compose up -d --build
```

Run smoke tests:

```bash
bash smoke-test.sh
```

## What gets validated

1. Sidecar HTTP health endpoint.
2. Guard decision on clean payload.
3. Guard decision on malicious payload (`safe=false` with `SHADOW_MODE=false`).
4. MCP `tools/list` exposes built-in tools.
5. MCP `tools/call` returns structured output from `safellm.guard_decide`.

## Manual MCP call example

```bash
docker compose exec -T sidecar sh -lc \
  "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}' | python -m sidecar.mcp"
```

## Main tuning knobs

- `SIDECAR_HTTP_PORT` (default `18000`)
- `SHADOW_MODE` (default `false`)

## Cleanup

```bash
docker compose down -v
```
