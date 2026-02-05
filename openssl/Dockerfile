# syntax=docker/dockerfile:1.7

ARG OPENSSL_TAG="OpenSSL_1_1_1w"
ARG OPENSSL_DIR="openssl-1.1.1w"

# ===== build stage =====
FROM ubuntu:24.04 AS build

ARG DEBIAN_FRONTEND=noninteractive
ARG OPENSSL_TAG
ARG OPENSSL_DIR

# 最初に ca-certificates を http 経由で取る
RUN --mount=type=cache,target=/var/cache/apt \
    --mount=type=cache,target=/var/lib/apt \
    rm -f /etc/apt/apt.conf.d/docker-clean && \
    apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates

# 速いミラー（必要なら書き換えてください）
RUN sed -i.bak -r 's@http://(jp\.)?archive\.ubuntu\.com/ubuntu/?@https://ftp.udx.icscoe.jp/Linux/ubuntu/@g' /etc/apt/sources.list.d/ubuntu.sources

# MinGW cross toolchain + build essentials for OpenSSL (Perl is required)
RUN --mount=type=cache,target=/var/cache/apt \
    --mount=type=cache,target=/var/lib/apt \
    rm -f /etc/apt/apt.conf.d/docker-clean && \
    apt-get update && apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl xz-utils \
    perl make \
    gcc g++ \
    mingw-w64 \
    file \
    tar gzip \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Fetch OpenSSL source tarball (as requested)
RUN curl -L "https://github.com/openssl/openssl/releases/download/${OPENSSL_TAG}/${OPENSSL_DIR}.tar.gz" -o /build/openssl.tar.gz

RUN tar -xzf /build/openssl.tar.gz -C /build \
 && test -d "/build/${OPENSSL_DIR}"

WORKDIR /build/${OPENSSL_DIR}
# ---- Choose target triplet here (x86_64-w64-mingw32) ----
# If you need 32-bit later: i686-w64-mingw32 and Configure target "mingw".
ENV TARGET_TRIPLET="x86_64-w64-mingw32"
ENV PREFIX="/opt/openssl/${OPENSSL_DIR}/${TARGET_TRIPLET}"
ENV OPENSSLDIR="/opt/openssl/${OPENSSL_DIR}/ssl"

# Configure flags:
# - mingw64 + --cross-compile-prefix per NOTES-WINDOWS.md (Linux cross)
# - shared enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers (as requested)
# - no-tests to save time (optional; remove if you want)
#
# Static libs (.a) are built regardless; "shared" additionally builds DLLs/import libs.
RUN perl Configure mingw64 \
    --cross-compile-prefix=${TARGET_TRIPLET}- \
    --prefix="${PREFIX}" \
    --openssldir="${OPENSSLDIR}" \
    shared enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers \
    no-tests

RUN make -j"$(nproc)"
RUN make install_sw

RUN mkdir -p "/stage/openssl"
RUN cp -rT ${PREFIX} /stage/openssl


# Also drop a tiny "how to link" note (optional)
RUN mkdir -p /stage/openssl/_notes \
 && printf "%s\n" \
"Static link on Windows typically needs: -lws2_32 -lgdi32 -ladvapi32 -lcrypt32 -luser32" \
"See OpenSSL NOTES-WINDOWS.md for details." \
> /stage/openssl/_notes/linking.txt

# Create outputs:
# 1) Directory tree (handy if you want to copy as-is)
# 2) Tarball with normalized ownership/permissions (recommended for Windows extraction)
RUN mkdir -p /out \
 && cp -r /stage/openssl /out/openssl \
 && tar -czf /out/openssl-${OPENSSL_DIR}-${TARGET_TRIPLET}.tar.gz \
      --numeric-owner --owner=0 --group=0 \
      --mode='u=rwX,go=rX' \
      -C /stage openssl \
 && (cd /out && sha256sum "openssl-${OPENSSL_DIR}-${TARGET_TRIPLET}.tar.gz" > "openssl-${OPENSSL_DIR}-${TARGET_TRIPLET}.tar.gz.sha256")


ARG OPENSSL_DIR
ENV TARGET_TRIPLET="x86_64-w64-mingw32"
ENV PREFIX="/opt/openssl/${OPENSSL_DIR}/${TARGET_TRIPLET}"


# Default: keep artifacts in /out
WORKDIR /out
