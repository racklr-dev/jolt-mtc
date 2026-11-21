FROM debian:stable-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl3 zlib1g libzstd1 libncurses6 libuuid1 \
 && rm -rf /var/lib/apt/lists/*
COPY mtc-ca /usr/local/bin/mtc-ca
ENTRYPOINT ["/usr/local/bin/mtc-ca"]
