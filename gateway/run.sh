#!/bin/sh
# Build and (re)start the gateway container as "a10-gateway".
# Needs the sandbox API running on the host (port 9000) with the same SANDBOX_API_KEY.
set -e
cd "$(dirname "$0")"
: "${SANDBOX_API_KEY:?set SANDBOX_API_KEY to the sandbox API key}"
: "${GATEWAY_ADMIN_KEY:=devadmin}"
[ -n "$APPROVED_DESTINATIONS" ] || APPROVED_DESTINATIONS='{"api.internal.example": "sensitive"}'
export APPROVED_DESTINATIONS GATEWAY_ADMIN_KEY OFFLINE
: "${OFFLINE:=1}"
: "${PROMPT_GUARD:=0}"
export PROMPT_GUARD
docker build -q --build-arg PROMPT_GUARD="$PROMPT_GUARD" -t a10-gateway:latest . >/dev/null
docker rm -f a10-gateway >/dev/null 2>&1 || true
docker run -d --name a10-gateway \
  --add-host host.docker.internal:host-gateway \
  -p 127.0.0.1:8080:8080 \
  -v "$PWD/workspace:/data:ro" \
  -e SANDBOX_API_URL="${SANDBOX_API_URL:-http://host.docker.internal:9000}" \
  -e SANDBOX_API_KEY -e GATEWAY_ADMIN_KEY -e APPROVED_DESTINATIONS -e OFFLINE \
  ${RISK_URL:+-e RISK_URL} \
  -e PROMPT_GUARD ${PROMPT_GUARD_THRESHOLD:+-e PROMPT_GUARD_THRESHOLD} ${PROMPT_GUARD_MAX_CHARS:+-e PROMPT_GUARD_MAX_CHARS} \
  ${PROMPT_GUARD_WINDOW:+-e PROMPT_GUARD_WINDOW} \
  -v a10-hf-cache:/hf \
  ${LLM_UPSTREAM:+-e LLM_UPSTREAM} ${ANTHROPIC_API_KEY:+-e ANTHROPIC_API_KEY} \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
  a10-gateway:latest >/dev/null
# Optional: also join the network a mock model upstream lives on (gateway/mock_upstream.sh).
if [ -n "$UPSTREAM_NETWORK" ]; then docker network connect "$UPSTREAM_NETWORK" a10-gateway; fi
[ -n "$ANTHROPIC_API_KEY" ] || echo "note: ANTHROPIC_API_KEY not set; /llm will return 503"
echo "gateway running: http://127.0.0.1:8080 (admin key: $GATEWAY_ADMIN_KEY)"
