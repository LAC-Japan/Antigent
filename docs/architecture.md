# Architecture

Antigent is the **defense plane** of an adversarial lab: an AI agent that watches a
target environment and interferes with an attacker's progress. The defense image ships
without a target or attacker. A separately built Attack Box sample is provided as an
optional example; it is not part of the defense container or its trust boundary.

**Language:** English | [日本語](ja/architecture.md)

```
            your attacker (any agent / human)
                 |  commands over the target's exposed ports
                 v
   +-----------------------------+        Docker API (logs, diff, exec)
   |   your target containers    | <---------------------------+
   | (scenario adapter's roles)  |                             |
   +-----------------------------+                             |
                 ^   logs / fs changes                         |
                 |                                             |
   +-----------------------------+   runs/defense/*.jsonl   +--+----------------+
   | sensor daemon  (always-on)  | ------------------------> | Defense Gateway  |
   +-----------------------------+                           | (MCP server)     |
                 |  elevated events                          |  allow-list exec |
                 v                                           +--^-----------+--+
   +-----------------------------+                              | submit_turn |
   | driver (one turn per burst) | --- `opencode run` ------->  | OpenCode    |
   +-----------------------------+                              | (Antigent)  |
                                                                 +------------+
   +-----------------------------+
   | console (viewer + eval)     |  reads runs/ only, no Docker, no exec
   +-----------------------------+
```

## Observation and intervention boundary (O1)

- Antigent sees **defender-side telemetry only**: the target containers' logs and
  filesystem changes (plus a network tap). It never reads the attacker's
  own command stream.
- The attacker stream (`runs/attacker/attacker.jsonl`) exists for the audience and for
  evaluation. Only the Console and `eval/` read it. The `antigent` container mounts
  `runs/defense/` only, so the boundary holds at the filesystem level.
- Antigent acts on the target exclusively through the Defense Gateway, which runs
  `docker exec` into the containers the scenario declares as `exec_roles` — nothing
  else (the `antigent-*` containers themselves are refused).

## Components

| Component | Role |
| --- | --- |
| `gateway/sensor.py` | Always-on collector: container logs, `docker diff`, network flows. Writes `runs/defense/sensor.jsonl` with a `level` (`baseline` / `raw` / `elevated`) and `internal` tags. Runs the adapter-declared clean calibration on fresh state and persists `sensor.baseline.json` / readiness status. |
| `gateway/baseline.py` | Generic recurring-event learner and exact-match filter. The Scenario Adapter owns duration, repetition policy, event kinds, and compared attributes; learned events do not feed detection windows or driver activity. |
| `gateway/driver.py` | Starts ONE `opencode run` turn per burst of elevated events (debounced), or periodically while ordinary activity continues. Links each action's post-action reobservation itself (no model turn), ends a turn once its submission is accepted, and runs one final reobservation turn after the attack. Turns are recorded in `runs/defense/driver.jsonl`. |
| `gateway/defense_gateway.py` | MCP server with three tools: `describe_scenario`, `observe_events`, `submit_turn`. Executes at most one reserved typed operation per turn through the Scenario Adapter and records assessments / decisions / actions. |
| `gateway/intervention_gate.py` | Fail-closed, persistent typed-action reservations. Enforces one action per observation turn, target/payload deduplication, and serial reobservation. |
| `gateway/netsensor.py` | Network tap (always started): captures HTTP requests and TCP connections on the Docker bridges into `runs/defense/net/flows.jsonl`. |
| `server.py`, `static/`, `console/` | Console: live viewer over `runs/`. In the container it is viewer-only. |
| `eval/metrics.py` | Summary of one run (detection lag, interventions, honeytoken use): `python3 eval/metrics.py runs/demo`. |
| `scenarios/<name>/` | Scenario Adapter: which containers are the roles, which sensors watch them, how log lines become events (`scenario.json`), the typed operations with their roles, target fields and the form shown to the agent (`adapter.py`), plus scenario context for the agent (`context.md`). The core (gateway, driver, policy, skills) names none of them. The context describes only the defended environment (configuration, telemetry, supported actions), never an attack path, the environment's weaknesses or expected attacker behaviour. |
| `eval/` | Stream merge, metrics, run comparison, attacker-log validation. |

## Policy and skills

The agent's behavior lives in `AGENTS.md` (the loop: observe -> predict -> pre-empt ->
submit once) and `.opencode/skills/` (the response directions: artifact-path decoys,
in-environment instructions, common deception rules, containment, observe-only).
The gateway enforces the role allow-list and one accepted submit per turn. Typed protocols
add persistent reservations and adapter-mediated native operations; they do not infer
capabilities from a Skill name. The defender's harness is OpenCode; what Antigent assumes about
the harness is listed as constraints in [harness.md](harness.md).

## Typed actions, evidence, and recovery

The CI/CD Goat adapter implements `gitea_repo_file` and `jenkins_disable_job`. Gitea file
creation uses an exact native repository/ref/path and an independently read back commit.
Jenkins containment uses an exact WorkflowJob and API readback. Both record native
observations and side-effect snapshots without treating process exit 0 as target delivery.

`runs/defense/intervention_state.json` links action IDs, payload/target hashes, native
observation IDs, and reobservation links. `runs/defense/defense.jsonl` records accepted
turns and native delivery/containment observations. After the attacker stops, the driver's
final reobservation writes `driver.finalized.json`. The demo runner then invokes the adapter's
recovery command, which writes `recovery.json`; `stop` retries incomplete recovery and skips an
already complete report. Conflicting or incomplete recovery is reported rather than hidden.
Recovery completion does not itself prove containment effectiveness: the report keeps
`containment_final[].status` separate.

## Run manifest

Every gateway start appends an `agent_start` record to `runs/defense/defense.jsonl`
with the policy hash (AGENTS.md + skills), the model name, the scenario name/hash and
the mechanism version, so any exported window is self-describing. No secrets are
recorded.

## Trust boundaries

- The target and the defense plane share one Docker daemon; the `socket-proxy`
  container (the API guard in `apiguard/`) is the only holder of `docker.sock` and allows only ps / inspect / logs / diff and exec into the declared targets.
- The Console has no Docker access and no command execution code (display-only).
- The attacker must reach the target only through its exposed ports and must have no
  path to the Docker socket or the `antigent-*` containers.
