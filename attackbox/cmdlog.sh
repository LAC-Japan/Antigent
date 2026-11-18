# SPDX-License-Identifier: Apache-2.0
# Bash command producer for runs/attacker/attacker.jsonl (one JSON object per command).
# Source this file; do not execute it as a standalone program.

# A child Bash inherits __ATTACKBOX_PARENT, preventing duplicate nested records.
# The loaded guard also handles login shells that read both profile and bashrc.
[[ -n ${__ATTACKBOX_LOADED:-} || -n ${__ATTACKBOX_PARENT:-} ]] && return 0
__ATTACKBOX_LOADED=1
export __ATTACKBOX_PARENT=1

__ATTACKBOX_LOG_DIR=/var/log/attackbox
if [[ -n ${SSH_CONNECTION:-} ]]; then
  __ATTACKBOX_VIA=ssh
else
  __ATTACKBOX_VIA=exec
fi

# Arguments: event, id, command (start/cmd only), exit status (end/cmd only).
__attackbox_emit() {
  jq -nc \
    --arg event "$1" \
    --arg id "$2" \
    --arg command "${3:-}" \
    --arg status "${4:-}" \
    --arg via "${__ATTACKBOX_VIA}" \
    --arg user "$(id -un)" \
    --arg cwd "${PWD}" \
    '{ts: now, event: $event, id: $id, via: $via, user: $user, cwd: $cwd}
     + (if $event == "end" then {} else {command: $command} end)
     + (if $status == "" then {} else {exit_code: ($status | tonumber)} end)' \
    >> "${__ATTACKBOX_LOG_DIR}/attacker.jsonl" 2>/dev/null || true
}

if [[ -n ${BASH_EXECUTION_STRING:-} ]]; then
  # OpenCode and `docker compose exec ... bash -c ...` arrive here. The end event
  # has the same id as start, and output files use that id as required by the API.
  __ATTACKBOX_COMMAND_ID="$(date +%s%N)-$$"
  __attackbox_emit start "${__ATTACKBOX_COMMAND_ID}" "${BASH_EXECUTION_STRING}"
  exec > >(tee -a "${__ATTACKBOX_LOG_DIR}/out/${__ATTACKBOX_COMMAND_ID}.out")
  exec 2> >(tee -a "${__ATTACKBOX_LOG_DIR}/out/${__ATTACKBOX_COMMAND_ID}.err" >&2)
  trap '__attackbox_emit end "${__ATTACKBOX_COMMAND_ID}" "" "$?"' EXIT
elif [[ $- == *i* ]]; then
  # An interactive command is emitted only after it has finished, making it a
  # schema-compliant cmd event rather than a premature start/end pair.
  HISTFILE=/dev/null
  HISTCONTROL=
  __ATTACKBOX_HISTORY_NUMBER=
  __attackbox_prompt() {
    local status=$? entry number command
    entry=$(HISTTIMEFORMAT= builtin history 1)
    if [[ ${entry} =~ ^[[:space:]]*([0-9]+)\*?[[:space:]]+(.*)$ ]]; then
      number=${BASH_REMATCH[1]}
      command=${BASH_REMATCH[2]}
      if [[ -n ${command} && ${number} != "${__ATTACKBOX_HISTORY_NUMBER}" ]]; then
        __ATTACKBOX_HISTORY_NUMBER=${number}
        __attackbox_emit cmd "$(date +%s%N)-$$" "${command}" "${status}"
      fi
    fi
  }
  PROMPT_COMMAND="__attackbox_prompt${PROMPT_COMMAND:+;${PROMPT_COMMAND}}"
fi
