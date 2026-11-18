<!-- SPDX-License-Identifier: Apache-2.0 -->
# Public Attack Box sample

This is a self-contained, target-agnostic example of an AI/human attacker plane for
an **explicitly authorized, isolated lab**. It supplies a shell, OpenCode, common
network clients, and pinned secret scanners. It contains no target application,
target solution, defense telemetry, or private range component.

**Language:** English | [日本語](../../docs/ja/attackbox.md)

The only output shared with the Defense Plane is the schema-defined command stream
at `runs/attacker/`. The attacker has no Docker socket and joins only the internal
network `antigent-attack-lab`, to which the operator attaches the authorized targets.

## Defaults and boundaries

- `docker compose exec` is the access method. No SSH server, password login, or host
  port is configured; the image includes only an SSH client for authorized targets.
- `AUTHORIZED_TARGETS` is blank by default, so the supplied agent role must ask for
  scope rather than probe anything.
- **Egress is enforced by Docker, not by the prompt.** `antigent-attack-lab` is an
  `internal` bridge with `com.docker.network.bridge.inhibit_ipv4`: no default route,
  no external DNS, and no address of the Docker host is reachable (an `internal`
  network alone still reaches the host's bridge address). The only way out is
  `egress-proxy`, which accepts HTTPS `CONNECT` to `ATTACKER_EGRESS_ALLOW` (the LLM
  API) and refuses web search, plain HTTP, other hosts and ports, IP literals, and
  names resolving to private or metadata addresses. Decisions are logged to
  `runs/egress/egress.jsonl` (`allow` when a tunnel opens, `close` when it ends). OpenCode's
  model catalog (`models.opencode.ai`) is not allowed, so the box sets
  `OPENCODE_DISABLE_MODELS_FETCH=1` and OpenCode uses the catalog bundled with the pinned release.
- Only targets you attach are reachable:
  `docker network connect antigent-attack-lab <target-container>`.
- Model credentials in `.env` are readable by every command the agent runs. Use a
  dedicated low-limit attacker key, never the defender's.
- The container sets `no-new-privileges`; interactive agent commands run as the
  unprivileged `attacker` user.
- Public CA roots work without extra files. TLS verification is always enabled.

## Configure and start

Run these commands from `examples/attacker/` after your isolated target lab is
running:

```sh
cp .env.example .env
```

Edit `.env`:

1. Set `ATTACKER_EGRESS_ALLOW` to your model API host (default `opencode.ai`).
2. Set `AUTHORIZED_TARGETS` to a comma-separated allowlist such as
   `target.lab.internal,http://target.lab.internal:8080`. Use only names belonging
   to your lab; network reachability alone is not authorization.
3. Keep the pinned tool versions unless deliberately upgrading them.

Build and start the sample, then launch OpenCode as the unprivileged user:

```sh
docker compose up -d --build
docker network connect antigent-attack-lab <target-container>
docker compose exec -it --user attacker attackbox opencode
```

Before `docker compose down`, detach the targets again
(`docker network disconnect antigent-attack-lab <target-container>`).

The default `opencode.free.jsonc` lets you choose an available model with `/models`.
To use an independent OpenAI-compatible endpoint instead, set these values in
`.env`:

```dotenv
ATTACKER_OPENCODE_CONFIG=opencode.lab.jsonc
ATTACKER_LLM_BASE_URL=https://llm.lab.invalid/v1
ATTACKER_LLM_API_KEY=replace-locally
ATTACKER_LLM_MODEL_ID=your-lab-model
```

Keep `.env` local. The two model configurations deny OpenCode's web tools; normal
shell commands still remain subject to `AGENTS.md` and the target allowlist.

## Shell use and command ground truth

Prefer explicit unprivileged exec sessions:

```sh
docker compose exec --user attacker attackbox bash -c 'printf "hello\n"'
docker compose exec -it --user attacker attackbox bash
```

`BASH_ENV`, `/etc/bash.bashrc`, and `/etc/profile.d/` load `cmdlog.sh`. OpenCode's
Bash tool and `docker compose exec ... bash -c ...` therefore produce `start` and
`end` records with a shared command ID. Interactive Bash produces one `cmd` record
after each command finishes. Standard output and error are also passed through
unchanged to the caller.

The hook covers top-level `bash -c` commands and interactive Bash. Directly executed
non-Bash programs and script-internal child shells are outside its record; nested
Bash shells are suppressed to avoid duplicates. Launch OpenCode itself as a
directly executed program (`docker compose exec --user attacker attackbox opencode
run ...`), never through a wrapper shell: a wrapper marks every OpenCode tool call
as a nested shell and silently suppresses its record. This is operational ground
truth for the supported OpenCode/exec path, not a tamper-evident audit log.

### JSONL contract

The container writes `/var/log/attackbox/attacker.jsonl`, which the Compose mount
exposes at `defense-plane/runs/attacker/attacker.jsonl`. Each line is one record:

| Field | Meaning |
| --- | --- |
| `ts` | Unix time in seconds, including fractions |
| `event` | `start`, `end`, or a completed interactive `cmd` |
| `id` | Unique command ID; a command's `start` and `end` share it |
| `command` | Command text on `start` and `cmd` records |
| `exit_code` | Integer status on `end` and `cmd` records |
| `via` | Arrival path, normally `exec` in this sample |
| `user`, `cwd` | Shell identity and working directory |

For a `bash -c` command, optional output files are written as
`out/<id>.out` and `out/<id>.err` beside the JSONL file. Only
`runs/attacker/` is mounted; no other run or defense directory is available.

## Optional combined CA bundle

The default `CA_BUNDLE_PATH` is `/etc/ssl/certs/ca-certificates.crt`. If your lab
uses TLS inspection, provide a PEM bundle containing both the public roots and your
additional trusted root:

1. Copy it to `examples/attacker/combined-ca-bundle.pem`.
2. Uncomment the read-only `combined-ca-bundle.pem` volume in
   `examples/attacker/docker-compose.yml`.
3. Set `CA_BUNDLE_PATH=/etc/attackbox/ca/combined-ca-bundle.pem` in `.env`.
4. Recreate the container. Startup fails if the selected bundle is unreadable.

The runtime CA path is applied consistently to curl, Git, Python requests,
OpenSSL-based tools, and Node. Image builds use public roots by default. To verify
OpenCode and scanner downloads through an additional trusted root, place
`combined-ca-bundle.pem` in a separate local directory and set
`ATTACKER_CA_CONTEXT` to that directory; the build mounts it only for verified
downloads. Do not bypass certificate checks to make a build or command succeed.

## License

The self-authored sample files are licensed under Apache License 2.0; see
`../../LICENSE`. Downloaded tools retain their respective upstream licenses.
