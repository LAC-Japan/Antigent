#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

readonly LOG_DIR=/var/log/attackbox
readonly CA_FILE="${SSL_CERT_FILE:-/etc/ssl/certs/ca-certificates.crt}"

# Fail closed if an explicitly selected CA bundle was not mounted. The default is
# Debian's public CA bundle, so no private CA is needed for normal use.
if [[ ! -r "${CA_FILE}" ]]; then
  printf 'attackbox: CA bundle is not readable: %s\n' "${CA_FILE}" >&2
  exit 1
fi

# The bind-mounted log can arrive owned by root. Only this directory is shared with
# the console; it is deliberately separate from all target and defense state.
install -d -m 1777 "${LOG_DIR}" "${LOG_DIR}/out"
touch "${LOG_DIR}/attacker.jsonl"
chmod 1777 "${LOG_DIR}" "${LOG_DIR}/out"
chmod 0666 "${LOG_DIR}/attacker.jsonl"

# OpenCode runs as the unprivileged attacker user via docker compose exec --user.
# Named volumes may need their initial ownership adjusted on first use.
chown -R attacker:attacker \
  /home/attacker/.cache \
  /home/attacker/.config \
  /home/attacker/.local
chown attacker:attacker /home/attacker/work

printf 'attackbox ready; use docker compose exec --user attacker attackbox ...\n'
exec "$@"
