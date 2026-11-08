#!/bin/sh
# Start the mock model API as container "a10-mock-llm" on network "a10-upstream".
# Then start the gateway against it:
#   LLM_UPSTREAM=http://a10-mock-llm:8090 ANTHROPIC_API_KEY=mock-key UPSTREAM_NETWORK=a10-upstream ./gateway/run.sh
set -e
cd "$(dirname "$0")"
docker build -q -t a10-gateway:latest . >/dev/null
docker network inspect a10-upstream >/dev/null 2>&1 || docker network create a10-upstream >/dev/null
docker rm -f a10-mock-llm >/dev/null 2>&1 || true
docker run -d --name a10-mock-llm --network a10-upstream \
  -e MOCK_KEY=mock-key -e MOCK_TTFT_MS="${MOCK_TTFT_MS:-500}" -e MOCK_TOKEN_MS="${MOCK_TOKEN_MS:-20}" \
  -v "$PWD/mock_llm.py:/app/mock_llm.py:ro" \
  a10-gateway:latest uvicorn mock_llm:app --host 0.0.0.0 --port 8090 >/dev/null
echo "mock model API: http://a10-mock-llm:8090 on network a10-upstream (key: mock-key)"
