#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

podman rm -f mtc-envoy mtc-sidecar 2>/dev/null || true
podman network rm mtc-net 2>/dev/null || true
podman network create mtc-net >/dev/null

podman build -q -t mtc-sidecar -f demo/sidecar.Containerfile .
podman run -d --name mtc-sidecar --network mtc-net -p 8080:8080 mtc-sidecar
podman run -d --name mtc-envoy --network mtc-net -p 10000:10000 \
  -v "$PWD/demo/envoy.yaml:/etc/envoy/envoy.yaml:ro" \
  docker.io/envoyproxy/envoy:v1.31-latest >/dev/null

for _ in $(seq 1 60); do
  curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1 && break
  sleep 1
done

curl -s http://127.0.0.1:8080/client-cert -o /tmp/client.pem
CERT=$(python3 -c "import urllib.parse;print(urllib.parse.quote(open('/tmp/client.pem').read()))")

echo "== with MTC certificate =="
curl -s -H "x-mtc-cert: $CERT" http://127.0.0.1:10000/ -w '\nHTTP %{http_code}\n'
echo "== without certificate =="
curl -s -o /dev/null -w 'HTTP %{http_code}\n' http://127.0.0.1:10000/
