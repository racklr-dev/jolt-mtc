#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

podman rm -f mtc-nginx mtc-sidecar 2>/dev/null || true
podman network rm mtc-net 2>/dev/null || true
podman network create mtc-net >/dev/null

mkdir -p demo/certs
openssl req -x509 -newkey rsa:2048 -keyout demo/certs/server.key \
  -out demo/certs/server.crt -days 1 -nodes -subj "/CN=localhost" 2>/dev/null

podman build -q -t mtc-sidecar -f demo/sidecar.Containerfile .
podman run -d --name mtc-sidecar --network mtc-net -p 8080:8080 mtc-sidecar
podman run -d --name mtc-nginx --network mtc-net -p 8443:8443 \
  -v "$PWD/demo/nginx.conf:/etc/nginx/nginx.conf:ro" \
  -v "$PWD/demo/certs:/certs:ro" \
  -v "$PWD/demo/protected.txt:/html/protected.txt:ro" \
  docker.io/library/nginx >/dev/null

for _ in $(seq 1 60); do
  curl -sf http://127.0.0.1:8080/health >/dev/null 2>&1 && break
  sleep 1
done

curl -s http://127.0.0.1:8080/client-cert -o /tmp/client.pem
CERT=$(python3 -c "import urllib.parse;print(urllib.parse.quote(open('/tmp/client.pem').read()))")

echo "== with MTC certificate =="
curl -sk -H "X-MTC-Cert: $CERT" https://127.0.0.1:8443/protected -w '\nHTTP %{http_code}\n'
echo "== without certificate =="
curl -sk -o /dev/null -w 'HTTP %{http_code}\n' https://127.0.0.1:8443/protected
