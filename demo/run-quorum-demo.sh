#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

podman rm -f mtc-site mtc-ca mtc-w1 mtc-w2 mtc-w3 2>/dev/null || true
podman network rm mtc-net 2>/dev/null || true
podman network create mtc-net >/dev/null
mkdir -p demo/data demo/w1 demo/w2 demo/w3

podman build -t mtc-ca -f demo/ca.Containerfile . >/dev/null 2>&1
podman build -t mtc-cosigner -f demo/cosigner.Containerfile . >/dev/null 2>&1

# three witness cosigners
podman run -d --name mtc-w1 --network mtc-net -p 8081:8080 \
  -e MTC_DATA_DIR=/data -e MTC_CA_URL=http://mtc-ca:8080 -e MTC_COSIGNER_ID=32473.1.101 \
  -v "$PWD/demo/w1:/data" mtc-cosigner
podman run -d --name mtc-w2 --network mtc-net -p 8082:8080 \
  -e MTC_DATA_DIR=/data -e MTC_CA_URL=http://mtc-ca:8080 -e MTC_COSIGNER_ID=32473.1.102 \
  -v "$PWD/demo/w2:/data" mtc-cosigner
podman run -d --name mtc-w3 --network mtc-net -p 8083:8080 \
  -e MTC_DATA_DIR=/data -e MTC_CA_URL=http://mtc-ca:8080 -e MTC_COSIGNER_ID=32473.1.103 \
  -v "$PWD/demo/w3:/data" mtc-cosigner

# CA requires its own cosignature + a quorum of 2 witnesses
podman run -d --name mtc-ca --network mtc-net -p 8080:8080 \
  -e MTC_DATA_DIR=/data \
  -e MTC_COSIGNERS=http://mtc-w1:8080,http://mtc-w2:8080,http://mtc-w3:8080 \
  -e MTC_QUORUM=2 \
  -v "$PWD/demo/data:/data" mtc-ca

podman run -d --name mtc-site --network mtc-net -p 8443:8443 \
  -v "$PWD/demo/nginx-site.conf:/etc/nginx/nginx.conf:ro" \
  -v "$PWD/demo/site:/site:ro" \
  docker.io/library/nginx >/dev/null

for _ in $(seq 1 90); do
  curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1 && break
  sleep 1
done

ISSUE=$(curl -s -X POST -H 'Content-Type: application/json' --data '{"subject":"visitor.example.com"}' http://127.0.0.1:8080/issue)
echo "issue: $ISSUE"
IDX=$(echo "$ISSUE" | python3 -c 'import json,sys; print(json.load(sys.stdin)["index"])')
curl -s "http://127.0.0.1:8080/cert/$IDX" -o /tmp/visitor.pem
CERT=$(python3 -c "import urllib.parse;print(urllib.parse.quote(open('/tmp/visitor.pem').read()))")

echo "== demo website with a quorum-signed MTC certificate =="
curl -s -H "X-MTC-Cert: $CERT" http://127.0.0.1:8443/ -o /dev/null -w 'HTTP %{http_code}\n'
echo "== without a certificate =="
curl -s -o /dev/null -w 'HTTP %{http_code}\n' http://127.0.0.1:8443/
