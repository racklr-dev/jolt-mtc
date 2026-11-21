# The MTC verification sidecar binary in a glibc container with the libs its
# optional natives need (OpenSSL 3, zlib, zstd, ncurses, uuid).
FROM debian:stable-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl3 zlib1g libzstd1 libncurses6 libuuid1 \
 && rm -rf /var/lib/apt/lists/*
COPY mtc-service /usr/local/bin/mtc-service
ENTRYPOINT ["/usr/local/bin/mtc-service"]
