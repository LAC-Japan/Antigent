# Connecting the CI/CD Goat target

The bundled Scenario Adapter (`scenarios/cicd-goat/`) describes the
[CI/CD Goat](https://github.com/cider-security-research/cicd-goat) training
environment. This page covers the connection only; the environment's own
documentation covers its challenges.

**Language:** English | [日本語](ja/cicd-goat.md)

CI/CD Goat, its source, and its third-party container images are **not included** in
the Antigent distribution. Obtain and run them separately in an authorized lab, and
follow the upstream licenses and notices. Only Antigent's self-authored adapter is
bundled here.

## Roles

The adapter watches these containers of a running CI/CD Goat deployment:

| Role | Container | What the sensors read |
| --- | --- | --- |
| `gitea` | `gitea` | HTTP access log (auth failures, per-client requests), filesystem changes |
| `jenkins` | `jenkins-server` | build log, filesystem changes |
| `prod` | `prod` | filesystem changes (tamper detection) |

Other services (CTFd, GitLab, localstack, ...) are reachable by the attacker but not
observed through logs; `netsensor` makes their network flows visible.

## Requirements

- CI/CD Goat runs on the **same Docker daemon** as the defense plane (default compose
  project works; the adapter resolves containers by name).
- Ports (defaults): Gitea 3000, Jenkins 8080, CTFd 8000, prod 8008 / ssh 2222.
- Observation and the Gitea file operation use the Docker API (the API guard allows `exec`
  into the Gitea container only). Jenkins WorkflowJob containment additionally requires a
  Jenkins administrator credential: `JENKINS_URL` / `JENKINS_ADMIN_USER` /
  `JENKINS_ADMIN_PASSWORD` in `.env`. Keep it in the local `.env`.

## Wiring

`scenarios/cicd-goat/scenario.json` maps roles to containers and log rules:

- `roles.<name>.container` — container name as shown by `docker ps`
- `log_rules` — how lines become events (`auth-failure`, per-client `new-source`)
- `request_rules` — outside-client requests reported as their own event kind; here `repo-read`
  (repository clone/fetch or file read)
- `roles.<name>.sensors[].surface` — lines of an internal log that are still shown; here
  Jenkins pull-request builds as `pipeline-run`
- `triggers.kinds` — which event kinds start a driver turn (elevated)
- `baseline` — attacker-free calibration: 60 seconds, at least two identical observations
  over 20 seconds, and the exact attributes learned for access logs / network telemetry
- `internal.same_project` — containers of the target's own compose project are not
  treated as attacker traffic

The baseline covers recurring host polling such as Gitea `/user/events` and CTFd `/health`.
It does not suppress a whole client IP, authentication failures, filesystem changes, or
unlearned paths. Wait for `baseline.ready` before starting the attacker.

The adapter belongs to the CI/CD Goat deployment, not to one challenge. Challenges using
the same services and telemetry share this adapter even when their repositories,
credentials, flags, or attack objectives differ; do not fork it only for those differences.

If you run the target with different container names, set the corresponding
`*_CONTAINER` environment variables.

## Typed actions

The adapter accepts only these operations (no raw shell commands):

| Operation | Target | Native verification and recovery |
| --- | --- | --- |
| `gitea_repo_file` | Create one previously absent file at an exact repository / ref / path | Independently read back the commit; recover without overwriting a conflicting later commit |
| `jenkins_disable_job` | Disable one exact WorkflowJob | Read back state through the Jenkins API, check final build state, and re-enable when recovery is required |

The gateway enforces one action per observation turn, a reservation before execution,
deduplication of targets, and a read-only reobservation before another mutation; there is
no fixed limit on the number of attempts. Process exit 0, target delivery/containment,
attacker read/follow, and reobservation are separate evidence stages.

## What an engagement looks like

1. The attacker enumerates Gitea -> `new-source` / `recon-burst` events.
2. The driver starts a turn; Antigent predicts the next step (e.g. a CI credential in
   a repository) and may create a bounded repository decoy with `submit_turn`.
3. The attacker uses the decoy -> the Console flags the honeytoken; the defense log
   distinguishes target delivery, attacker read/follow, and reobservation evidence.
4. Antigent can only use the two operations above.

## Limitations

- Single Docker host; `netsensor` sees plain HTTP only (HTTPS/SSH are
  recorded as connections, not content) and performs no TCP reassembly.
- Targets living outside Docker (VMs) need a remote sensor and are out of scope.
