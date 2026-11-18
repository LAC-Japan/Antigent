# Security model

Antigent is a **lab defense plane**. It executes commands inside containers you
declare as target roles. Never point it at production systems.

**Language:** English | [日本語](ja/security.md)

## What Antigent can do

- Observe: the target containers' logs, filesystem diffs, and network flows on the host's
  Docker bridges.
- Act: only the typed operations the Scenario Adapter declares; raw commands are refused.
  For CI/CD Goat these are a new file in a Gitea repository (`docker exec` into the Gitea
  container via the `socket-proxy`, the only container holding `docker.sock`) and disabling
  one Jenkins job (Jenkins API).
- Recover: the CI/CD Goat adapter can verify final containment and restore its own typed
  changes from native before/after snapshots. Recovery refuses to overwrite a conflicting
  later Gitea commit and reports incomplete or unverified outcomes.

## What Antigent cannot do

- It cannot read the attacker's command stream. The `antigent` container mounts only
  `runs/defense/`; the attacker log (`runs/attacker/`) is for the Console and
  evaluation, unreachable from the agent.
- It cannot execute outside the allow-list. The gateway refuses actions whose target
  role is not executable, and refuses the `antigent-*` containers themselves. Typed
  protocols additionally require a persistent pre-execution reservation, reject duplicate
  operations, and block another mutation until reobservation completes.
- It has no shell of its own: the OpenCode configuration denies shell/edit/web tools
  for the defense agent; its only capabilities are the three gateway tools.

## Containment of the defense plane

| Component | Privileges |
| --- | --- |
| `antigent` (container `antigent-core`) | no Docker socket; reaches `socket-proxy:2375`; mounts gateway code, scenario, policy, and `runs/defense/` |
| `socket-proxy` (container `antigent-socket-proxy`; API guard, `apiguard/`) | holds `docker.sock`; only `ps` / `inspect` / `logs` / `diff` and `exec` into the declared target containers (`GUARD_EXEC_CONTAINERS`). Refuses create / start / kill / rm / cp / images / networks, privileged exec, and exec into privileged, Docker-socket-mounting or `antigent-*` containers. On an internal network without a host address, accepting only `antigent` |
| `console` | viewer-only; no Docker access (not on the guard's network), no command execution, no operator records; binds 127.0.0.1:8765; refuses foreign `Host` headers (DNS rebinding) and cross-site or non-JSON POSTs (CSRF) |
| `netsensor` | `network_mode: host`, `cap_drop: ALL` + `NET_RAW`; no Docker API |

## LLM credentials

- The defense agent's model credentials come from `.env` (see `.env.example`) and live
  only inside the defense plane containers. For Bedrock, use an IAM key scoped to
  `bedrock:InvokeModel*`.
- The Console's `runs/` export includes the run manifest: policy hash, model name and
  endpoint host — never API keys.

## Target credentials and run artifacts

- `jenkins_disable_job` needs `ANTIGENT_JENKINS_URL`,
  `ANTIGENT_JENKINS_ADMIN_USER`, and `ANTIGENT_JENKINS_ADMIN_PASSWORD`. Use a dedicated
  lab administrator credential with only the required target scope. Other typed operations
  do not require this credential.
- Keep `.env` and completed run artifacts out of public releases. Typed turn logs omit raw
  model text and tool payloads, but defense evidence intentionally includes markers and
  target-native outcome records and must still be reviewed before sharing.

## Attacker side (if you connect one)

- The attacker reaches the target only through its exposed ports — never the Docker
  socket, the `antigent-*` containers, or the defense network.
- The Attack Box sample enforces this with Docker networking: it joins only
  `antigent-attack-lab` (`internal` + `inhibit_ipv4`; no route to the Internet, no
  external DNS, no Docker host address) and reaches its LLM API through
  `egress-proxy`, which allows HTTPS `CONNECT` to the configured API hosts only.
  `live_demo.py run` probes this boundary from inside the box and refuses to start
  the attacker if any probe gets through. Decisions go to `runs/egress/egress.jsonl`
  (`allow` when a tunnel opens, `close` when it ends, `deny` with a reason). OpenCode's
  model catalog (`models.opencode.ai`) is not allowed; the box sets
  `OPENCODE_DISABLE_MODELS_FETCH=1` so OpenCode uses the catalog bundled with the pinned release.
- Credentials passed to the Attack Box are readable by the attacker agent. It gets
  only its own provider's key (never the defender's); use a low-limit key.
- Output files named in `attacker.jsonl` are read only as plain names (no `..`, no
  separators) and never through symlinks.
- The attacker writes only `runs/attacker/`.

## Console

The Console is display-only and has no command execution code: the former operator mode
(attacker/defender command inputs, holding commands, operator records) was removed. Its only state-changing request, **New session**, is
refused for foreign `Host` headers (DNS rebinding) and for cross-site or non-JSON POSTs.

## Known limits (isolated-lab assumptions)

- The attacker command record is written by a shell hook running as the attacker; it is
  ground truth for cooperative agents, not a tamper-proof audit log.
- Attacker-controlled text reaches the defense model through target telemetry. Prefer
  the typed protocols, which refuse raw commands.
- The `antigent` container itself has ordinary egress for its model API; its agent has
  no shell or web tools.
- `netsensor` uses host networking and promiscuous capture of the Docker
  bridges.

## Reporting

This package is published for research and training. Report vulnerabilities through
the repository's security policy or the channel supplied by your distributor. Do not
include credentials, private certificates, target flags, or sensitive run artifacts.
