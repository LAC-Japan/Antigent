# Antigent defense container: OpenCode (MCP client) + Defense Gateway (MCP server).
# v0.13: the defense bundle is BAKED INTO the image (build context = repo root), so the
# distributed artefact is the container itself. What is inside:
#   gateway/            Defense Gateway, sensor daemon, event-driven driver (mechanism, fixed)
#   AGENTS.md, .opencode/skills/   policy (the only layer an improvement loop may change)
#   opencode.lab.jsonc      OpenCode config: lab provider from env, shell/edit/webfetch denied
#   scenarios/          Scenario Adapters (cicd-goat bundled); select with ANTIGENT_SCENARIO
# runs/ is NOT in the image (.dockerignore) -- only runs/defense is mounted at run time,
# so Antigent can never read the attacker stream (O1 boundary).
FROM debian:bookworm-slim

# On egress-restricted hosts (TCP 443 only) or behind TLS-inspecting proxies, provide a
# combined CA bundle via the "ca" build context; apt then uses HTTPS with that bundle.
# Without a bundle the default Debian HTTP mirrors are used (see ca/README.md).
RUN --mount=type=bind,from=ca,target=/ca \
    if [ -f /ca/combined-ca-bundle.pem ]; then \
      sed -i 's|http://deb.debian.org|https://deb.debian.org|g; s|http://security.debian.org|https://security.debian.org|g' \
        /etc/apt/sources.list.d/debian.sources; \
      echo 'Acquire::https::CAInfo "/ca/combined-ca-bundle.pem";' > /etc/apt/apt.conf.d/99ca-bundle; \
    fi; \
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      bash ca-certificates curl git python3 unzip \
    && rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/99ca-bundle

# Runtime trust: the same bundle is added to the image's CA store, so OpenCode's model calls
# (Node/Bun, NODE_EXTRA_CA_CERTS) and curl/python also pass a TLS-inspecting proxy. Without a
# bundle this is a no-op and only the public roots are trusted.
RUN --mount=type=bind,from=ca,target=/ca \
    if [ -f /ca/combined-ca-bundle.pem ]; then \
      cp /ca/combined-ca-bundle.pem /usr/local/share/ca-certificates/antigent-ca-bundle.crt \
      && update-ca-certificates; \
    fi
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt

# Docker CLI only (static binary from the official image; Debian bookworm has no
# `docker-cli` package). The gateway uses it against the socket proxy, never a local daemon.
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker

# OpenCode 2 (official v2 installer), pinned to an explicit release. Empty or "latest" is
# refused (as in attackbox/Dockerfile) so a rebuild never silently picks up a new release.
# Optional: named build context "ca" holding a combined CA bundle (system roots + a
# TLS-inspecting proxy CA) for hosts behind such a proxy. Verification stays ON;
# without the bundle the system roots are used. See ca/README.md.
ARG OPENCODE_VERSION=2.3.0
# The installer is downloaded first and then run: with `curl | bash` a failed download (TLS
# inspection without a CA bundle, no route, ...) was swallowed and only a later check failed.
RUN --mount=type=bind,from=ca,target=/ca \
    if [ -f /ca/combined-ca-bundle.pem ]; then export CURL_CA_BUNDLE=/ca/combined-ca-bundle.pem; fi; \
    set -eu; \
    case "${OPENCODE_VERSION}" in ''|latest) \
      echo 'OPENCODE_VERSION must be an explicit release' >&2; exit 1;; \
    esac; \
    curl --proto '=https' --tlsv1.2 -fsSL -o /tmp/opencode-install.sh https://opencode.ai/v2/install \
      || { echo 'cannot download https://opencode.ai/v2/install (behind a TLS-inspecting proxy? see ca/README.md)' >&2; exit 1; }; \
    bash /tmp/opencode-install.sh --version "${OPENCODE_VERSION#v}"; \
    rm -f /tmp/opencode-install.sh; \
    test -x /root/.opencode/bin/opencode \
      || { echo "OpenCode installer did not produce /root/.opencode/bin/opencode (version ${OPENCODE_VERSION})" >&2; exit 1; }; \
    install -m 0755 /root/.opencode/bin/opencode /usr/local/bin/opencode; \
    opencode --version
# (The installer ignores OPENCODE_INSTALL_DIR and writes to /root/.opencode/bin, which other
#  users cannot read, so the binary is copied to /usr/local/bin.)

WORKDIR /antigent
COPY gateway/ /antigent/gateway/
COPY scenarios/ /antigent/scenarios/
COPY .opencode/ /antigent/.opencode/
COPY AGENTS.md opencode.lab.jsonc opencode.free.jsonc /antigent/
COPY antigent/entrypoint.sh /usr/local/bin/antigent-entrypoint
RUN chmod 0755 /usr/local/bin/antigent-entrypoint && mkdir -p /antigent/runs/defense

# The gateway talks to the socket proxy, never the host socket.
ENV DOCKER_HOST=tcp://socket-proxy:2375 \
    DEFENSE_LOG=/antigent/runs/defense/defense.jsonl \
    ANTIGENT_SCENARIO=/antigent/scenarios/cicd-goat \
    OPENCODE_CONFIG=/antigent/opencode.free.jsonc \
    SENSOR_STREAM=/antigent/runs/defense/sensor.jsonl
LABEL org.opencontainers.image.title="antigent-defense" \
      org.opencontainers.image.description="Antigent defense agent: OpenCode + Defense Gateway"
# v0.14: sensor daemon + event-driven driver (each Antigent turn is one `opencode run`).
CMD ["antigent-entrypoint"]
