# syntax=docker/dockerfile:1
# SPDX-License-Identifier: Apache-2.0
FROM debian:bookworm-slim

# Release versions are build arguments so an operator can deliberately upgrade them.
# The defaults are fixed; this sample never selects a moving "latest" release.
ARG OPENCODE_VERSION=2.3.0
ARG GITLEAKS_VERSION=8.21.2
ARG TRUFFLEHOG_VERSION=3.88.0
ARG TARGETARCH

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
      bash ca-certificates curl git jq less procps \
      iputils-ping dnsutils netcat-openbsd openssh-client \
      python3 python3-requests python3-yaml \
      nmap hydra unzip \
    && rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/99ca-bundle

# Runtime trust: behind a TLS-inspecting proxy the agent's model calls (egress-proxy only
# relays TLS) need the same CA. Without a bundle this is a no-op.
RUN --mount=type=bind,from=ca,target=/ca \
    if [ -f /ca/combined-ca-bundle.pem ]; then \
      cp /ca/combined-ca-bundle.pem /usr/local/share/ca-certificates/antigent-ca-bundle.crt \
      && update-ca-certificates; \
    fi

# OpenCode executes its shell inside this container. BASH_ENV below routes those
# commands through the same logger used by an operator's docker compose exec shell.
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

# Download pinned release archives over verified TLS. Nothing from these projects
# is vendored in this source tree.
RUN --mount=type=bind,from=ca,target=/ca set -eux; \
    if [ -f /ca/combined-ca-bundle.pem ]; then export CURL_CA_BUNDLE=/ca/combined-ca-bundle.pem; fi; \
    case "${TARGETARCH:-amd64}" in \
      amd64) gl_arch=x64; th_arch=amd64 ;; \
      arm64) gl_arch=arm64; th_arch=arm64 ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl --proto '=https' --tlsv1.2 -fsSL \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gl_arch}.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks; \
    curl --proto '=https' --tlsv1.2 -fsSL \
      "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${th_arch}.tar.gz" \
      | tar -xz -C /usr/local/bin trufflehog; \
    gitleaks version; \
    trufflehog --version

RUN useradd -m -s /bin/bash attacker \
    && install -d -o attacker -g attacker \
       /home/attacker/work \
       /home/attacker/.cache \
       /home/attacker/.config/opencode \
       /home/attacker/.local/share/opencode \
       /home/attacker/.local/state

COPY cmdlog.sh /etc/attackbox/cmdlog.sh
COPY entrypoint.sh /usr/local/bin/attackbox-entrypoint.sh
RUN chmod 0644 /etc/attackbox/cmdlog.sh \
    && chmod 0755 /usr/local/bin/attackbox-entrypoint.sh \
    && printf '%s\n' '. /etc/attackbox/cmdlog.sh' > /etc/profile.d/zz-attackbox-cmdlog.sh \
    && printf '%s\n' '. /etc/attackbox/cmdlog.sh' >> /etc/bash.bashrc

# Non-interactive Bash reads BASH_ENV. Interactive and login shells read the two
# startup files above. No SSH server or password login is installed.
ENV SHELL=/bin/bash \
    BASH_ENV=/etc/attackbox/cmdlog.sh

WORKDIR /home/attacker/work
ENTRYPOINT ["/usr/local/bin/attackbox-entrypoint.sh"]
CMD ["sleep", "infinity"]
