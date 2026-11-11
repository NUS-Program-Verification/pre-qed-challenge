# Build environment for all harnesses: clang + libFuzzer, Spot (LTL -> automata), node (LTL compiler),
# and the system libraries some subjects link against (coturn: OpenSSL, libevent; leptonica: image codecs;
# varnish: libpcre2-8, its header is in varnish/overlay).
FROM node:22-bookworm-slim AS node
FROM debian:trixie-slim
COPY --from=node /usr/local/ /usr/local/
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq clang llvm libclang-rt-dev libc6-dev libstdc++-14-dev \
      libssl-dev libevent-dev zlib1g-dev libpcre2-8-0 \
      libpng-dev libjpeg-dev libtiff-dev libwebp-dev libgif-dev libopenjp2-7-dev && \
    curl -fsSL https://www.lre.epita.fr/repo/debian.gpg -o /etc/apt/keyrings/lre-epita.gpg && \
    echo 'deb [signed-by=/etc/apt/keyrings/lre-epita.gpg] https://www.lre.epita.fr/repo/debian/ stable/' \
      > /etc/apt/sources.list.d/lre-epita.list && \
    apt-get update && apt-get install -y --no-install-recommends spot && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /work
