# SuperAwesomeMagicalSecurity server image (podman or docker).
#
#   podman build -t localhost/sams:latest .
#   podman run -d --name sams -p 8443:8443 -p 5514:5514/udp -p 5514:5514/tcp \
#       -v sams-data:/var/lib/sams:Z localhost/sams:latest
#
# Stage 1 compiles the Go agent and probe for linux/amd64 + arm64 and builds .deb/.rpm
# packages. The final image serves them at /downloads and /install.sh, so hosts can
# install the agent straight from your SAMS server.
#
# Behind a TLS-inspecting proxy, pass its CA without baking it into the image:
#   podman build --secret id=extra_ca,src=/path/to/proxy-ca.pem -t localhost/sams:latest .

ARG GO_IMAGE=docker.io/library/golang:1.24-bookworm
ARG PY_IMAGE=docker.io/library/python:3.12-slim-bookworm

FROM ${GO_IMAGE} AS agents
ARG VERSION=0.1.0
ARG NFPM_VERSION=v2.41.1
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
RUN --mount=type=secret,id=extra_ca,target=/run/secrets/extra_ca \
    if [ -s /run/secrets/extra_ca ]; then \
      cat /etc/ssl/certs/ca-certificates.crt /run/secrets/extra_ca > /tmp/ca.pem; export SSL_CERT_FILE=/tmp/ca.pem; \
    fi; \
    go install github.com/goreleaser/nfpm/v2/cmd/nfpm@${NFPM_VERSION} && rm -f /tmp/ca.pem
WORKDIR /src
COPY agent/ agent/
COPY probe/ probe/
RUN set -eux; mkdir -p /dist; \
    for arch in amd64 arm64; do \
      (cd agent && GOOS=linux GOARCH=$arch go build -ldflags "-s -w -X main.version=${VERSION}" \
          -o /dist/sams-agent-linux-$arch ./cmd/sams-agent); \
      (cd probe && GOOS=linux GOARCH=$arch go build -ldflags "-s -w -X main.version=${VERSION}" \
          -o /dist/sams-probe-linux-$arch ./cmd/sams-probe); \
      mkdir -p agent/bin/.pkg && cp /dist/sams-agent-linux-$arch agent/bin/.pkg/sams-agent; \
      for fmt in deb rpm; do \
        (cd agent && PKG_ARCH=$arch PKG_VERSION=${VERSION} nfpm package --config packaging/nfpm.yaml \
            --packager $fmt --target /dist/); \
      done; \
    done; \
    cp agent/packaging/install.sh /dist/install.sh; \
    cd /dist && sha256sum sams-* > SHA256SUMS

FROM ${PY_IMAGE}
LABEL org.opencontainers.image.title="sams-server" \
      org.opencontainers.image.description="SuperAwesomeMagicalSecurity: posture, attack paths, SIEM, remediation" \
      org.opencontainers.image.source="https://github.com/603madison/superawesomemagicalsecurity"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SAMS_DATA_DIR=/var/lib/sams SAMS_DIST_DIR=/opt/sams/dist SAMS_CONFIG=/etc/sams/sams.yaml
COPY server/ /src/server/
RUN --mount=type=secret,id=extra_ca,target=/run/secrets/extra_ca \
    if [ -s /run/secrets/extra_ca ]; then \
      cat /etc/ssl/certs/ca-certificates.crt /run/secrets/extra_ca > /tmp/ca.pem; export PIP_CERT=/tmp/ca.pem; \
    fi; \
    pip install '/src/server[ai]' && rm -rf /src /tmp/ca.pem \
 && useradd --system --uid 10001 --home-dir /var/lib/sams --shell /usr/sbin/nologin sams \
 && install -d -o sams -g sams -m 0750 /var/lib/sams && install -d -m 0755 /etc/sams
COPY --from=agents /dist /opt/sams/dist
USER 10001:10001
WORKDIR /var/lib/sams
VOLUME ["/var/lib/sams"]
EXPOSE 8443/tcp 5514/udp 5514/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8443/healthz', timeout=4)" || exit 1
ENTRYPOINT ["sams"]
CMD ["server", "--host", "0.0.0.0", "--port", "8443"]
