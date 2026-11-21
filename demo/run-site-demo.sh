#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

podman rm -f mtc-site mtc-ca 2>/dev/null || true
podman network rm mtc-net 2>/dev/null || true
podman network create mtc-net >/dev/null
mkdir -p demo/data

podman build -t mtc-ca -f demo/ca.Containerfile . >/dev/null 2>&1
podman run -d --name mtc-ca --network mtc-net -p 8080:8080 \
  -e MTC_DATA_DIR=/data \
  -v "$PWD/demo/data:/data" \
  mtc-ca
podman run -d --name mtc-site --network mtc-net -p 8443:8443 \
  -v "$PWD/demo/nginx-site.conf:/etc/nginx/nginx.conf:ro" \
  -v "$PWD/demo/site:/site:ro" \
  docker.io/library/nginx >/dev/null

for _ in $(seq 1 60); do
  curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1 && break
  sleep 1
done

ISSUE=$(curl -s -X POST -H 'Content-Type: application/json' --data '{"subject":"visitor.example.com"}' http://127.0.0.1:8080/issue)
IDX=$(echo "$ISSUE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["index"])')
curl -s "http://127.0.0.1:8080/cert/$IDX" -o /tmp/visitor.pem
CERT=$(python3 -c "import urllib.parse;print(urllib.parse.quote(open('/tmp/visitor.pem').read()))")

echo "== demo website with a valid MTC certificate =="
curl -s -H "X-MTC-Cert: $CERT" http://127.0.0.1:8443/ -w '\nHTTP %{http_code}\n' | head -9
echo "== without a certificate =="
curl -s -o /dev/null -w 'HTTP %{http_code}\n' http://127.0.0.1:8443/
