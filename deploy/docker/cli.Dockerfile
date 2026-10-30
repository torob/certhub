FROM docker.io/library/alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f AS certs

FROM scratch
ARG TARGETOS=linux
ARG TARGETARCH
ARG BINARY_DIR=bin
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY ${BINARY_DIR}/${TARGETOS}-${TARGETARCH}/certhub-cli /usr/local/bin/certhub-cli

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/certhub-cli"]
CMD ["run", "--config", "/etc/certhub/cli.yaml"]
