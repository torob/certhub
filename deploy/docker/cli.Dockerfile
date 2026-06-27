FROM docker.io/library/alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce AS certs

FROM scratch
ARG BINARY_DIR=bin
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY ${BINARY_DIR}/certhub-cli /usr/local/bin/certhub-cli

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/certhub-cli"]
CMD ["run", "--config", "/etc/certhub/cli.yaml"]
