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
WORKDIR /dummy-certs