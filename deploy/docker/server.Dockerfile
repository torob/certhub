FROM docker.io/library/alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f AS image-root
ARG TARGETOS=linux
ARG TARGETARCH
ARG BINARY_DIR=bin
RUN install -d -m 0755 /image-root/etc/certhub \
    && install -d -m 0755 /image-root/usr/local/bin \
    && install -d -o 65532 -g 65532 -m 0700 /image-root/var/lib/certhub/tls
COPY ${BINARY_DIR}/${TARGETOS}-${TARGETARCH}/certhub-server /image-root/usr/local/bin/certhub-server

FROM scratch
COPY --from=image-root /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=image-root /image-root/ /

USER 65532:65532
ENV CERTHUB_SERVER_CONFIG=/etc/certhub/server.yaml
ENTRYPOINT ["/usr/local/bin/certhub-server"]
CMD ["run"]
