# -----------------------------------------------------------------------------
# Multi-stage: build OpenSSL (enable SSLv3), build C++ server, then runtime image
# -----------------------------------------------------------------------------
ARG OPENSSL_TAG="OpenSSL_1_1_1w"
ARG OPENSSL_DIR="openssl-1.1.1w"


FROM debian:11 AS builder_dummy-certs
RUN mkdir /dummy-certs
WORKDIR /dummy-certs
RUN apt update
RUN apt -y install curl openssl
RUN curl https://larsenv.github.io/NintendoCerts/WII_NWC_1_CERT.p12 -LO
RUN openssl pkcs12 -in WII_NWC_1_CERT.p12 -passin pass:alpine -passout pass:alpine -out keys.txt
RUN sed -n '7,29p' keys.txt > nwc.crt
RUN sed -n '33,50p' keys.txt > nwc.key
RUN openssl genrsa -out server.key 1024
RUN echo "US\nWashington\nRedmond\nNintendo of America Inc.\nNintendo Wifi Network\n*.*.*\nca@noa.nintendo.com\n\n\n" | openssl req -new -key server.key -out server.csr
RUN openssl x509 -req -in server.csr -CA nwc.crt -CAkey nwc.key -CAcreateserial -out server.crt -days 3650 -sha1 -passin pass:alpine
RUN rm WII_NWC_1_CERT.p12 keys.txt nwc.key nwc.srl server.csr
RUN cat /dummy-certs/server.crt /dummy-certs/nwc.crt > /dummy-certs/server_with_chain.crt
WORKDIR /

FROM debian:11 AS builder_openssl
ARG OPENSSL_TAG
ARG OPENSSL_DIR
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential curl ca-certificates autoconf libtool libpcre3-dev pkg-config \
    python3 perl cmake git && rm -rf /var/lib/apt/lists/*

# download specific OpenSSL release (tag)
RUN curl -L "https://github.com/openssl/openssl/releases/download/${OPENSSL_TAG}/${OPENSSL_DIR}.tar.gz" -o /build/openssl.tar.gz && \
    tar xzf openssl.tar.gz && rm openssl.tar.gz

WORKDIR /build/${OPENSSL_DIR}
# enable ssl3 + weak ciphers as per your Dockerfile.txt approach
RUN ./config --prefix=/usr/local/openssl --openssldir=/usr/local/openssl shared enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers && \
    make -j$(nproc) && make install_sw && make install_ssldirs

# -----------------------------------------------------------------------------
# Build the C++ server using the built OpenSSL (inside builder stage)
# -----------------------------------------------------------------------------
FROM debian:11 AS builder_server
ARG OPENSSL_DIR
WORKDIR /opt
# copy openssl built files
COPY --from=builder_openssl /usr/local/openssl /usr/local/openssl


# install build tools
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake git ca-certificates && rm -rf /var/lib/apt/lists/*

# copy source (expecting repo root has src/ and CMakeLists.txt)
COPY src /opt/src
COPY CMakeLists.txt /opt/CMakeLists.txt

RUN echo 1.0.5

WORKDIR /opt
RUN mkdir -p build && cd build && \
    cmake .. -DOPENSSL_ROOT_DIR=/usr/local/openssl -DOPENSSL_INCLUDE_DIR=/usr/local/openssl/include && \
    make -j$(nproc)

# copy generated certs from openssl builder (or use provided certs)
RUN mkdir -p /opt/certs
# -----------------------------------------------------------------------------
# Runtime image: minimal runtime with our custom OpenSSL libs and server binary
# -----------------------------------------------------------------------------
FROM debian:11
ENV LD_LIBRARY_PATH=/usr/local/openssl/lib
# copy openssl runtime from builder
COPY --from=builder_openssl /usr/local/openssl /usr/local/openssl

# copy server binary and certs
COPY --from=builder_server /opt/build/dq9-server /usr/local/bin/dq9-server
COPY --from=builder_dummy-certs /dummy-certs/server.key /etc/ssl/private/server.key
COPY --from=builder_dummy-certs /dummy-certs/server.crt /etc/ssl/certs/server.crt
COPY --from=builder_dummy-certs /dummy-certs/nwc.crt /etc/ssl/certs/nwc.crt

# create dlc directory for server to serve files; allow user to mount in real files

# ensure ld picks up our OpenSSL
RUN echo "/usr/local/openssl/lib" > /etc/ld.so.conf.d/usr_local_openssl.conf && ldconfig

CMD ["/usr/local/bin/dq9-server", "443"]
