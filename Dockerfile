# Run the self-contained MTC demo binary in a minimal glibc container.
FROM debian:stable-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends libncurses6 libuuid1 \
 && rm -rf /var/lib/apt/lists/*
COPY mtc-bin /usr/local/bin/mtc-bin
ENTRYPOINT ["/usr/local/bin/mtc-bin"]
