# Agent harness (defender side)

Antigent's defender runs on **OpenCode** (pinned `OPENCODE_VERSION`, default 2.3.0). It is the only
harness that is supported and tested. This page states what the rest of Antigent assumes about
the harness, so that running the defender on another harness is a deliberate, documented change.

## Constraints a harness must meet

Any harness used for the defender must satisfy all of these. Items 1 and 2 are the security
boundary; do not relax them.

1. **Gateway as the only way to act.** The Defense Gateway (`python3 /antigent/gateway/defense_gateway.py`)
   is registered as a local MCP server over stdio, with the container's environment passed through
   (`DOCKER_HOST`, `DEFENSE_LOG`, `ANTIGENT_SCENARIO`, the `*_CONTAINER` names).
2. **Every other tool denied.** Shell, file read / edit / search / list, web fetch, web search, code
   search, LSP, task lists and sub-agents are denied. Only the gateway's tools and skill loading
   stay available. The agent then cannot reach the network, the containers or its own files except
   through the gateway's typed, audited operations.
3. **One non-interactive turn per call.** The driver starts the harness with a prompt argument,
   waits for it to exit, and reads the exit code. The call must not wait for terminal input.
4. **A persistent session.** A later call continues the previous conversation (OpenCode:
   `--continue`), and the harness compacts the context as it grows. The policy relies on the agent
   remembering the decoys it planted.
5. **Policy loading.** The harness reads `AGENTS.md` from the working directory (`/antigent`) as its
   instructions, and discovers the skills under `.opencode/skills/<name>/SKILL.md` (front matter
   `name`, `description`). If a harness reads another file or folder, link or copy these; do not
   edit them for the harness.
6. **Model and network settings from the environment.** The model is chosen per call
   (`ANTIGENT_MODEL`, OpenCode: `-m provider/model`), and proxy / CA settings in the container
   environment are honoured.
7. **Machine-readable output (optional).** With `ANTIGENT_OPENCODE_JSON=1` (default) the driver reads
   one JSON event per line (`--format json`) to profile each turn: LLM steps, tokens, tools and
   timing. Without it (`ANTIGENT_OPENCODE_JSON=0`) turns still run, but the Console shows no profile.

## Where OpenCode is assumed

| Place | What is OpenCode-specific |
|---|---|
| `gateway/driver.py` | `run_turn` builds the command (`OPENCODE_BIN run [--continue] [-m model] [--format json] <prompt>`); `parse_opencode_json` reads OpenCode's event format |
| `opencode.free.jsonc`, `opencode.lab.jsonc` | Constraints 1 and 2: MCP registration of the gateway and the tool deny list |
| `antigent/Dockerfile` | Installs the pinned OpenCode release |
| `AGENTS.md` | Says OpenCode compacts the session, and points to `.opencode/skills/`. Tool names appear in OpenCode's form (`antigent_observe_events`: MCP server name + tool name); other harnesses may name them differently |

## Using another harness

This is outside the supported configuration. If you do it:

- Meet every constraint above, and check constraint 2 by asking the agent to run a shell command or
  read a file: the request must be refused by the harness, not merely declined by the model.
- Change only the places in the table. Keep the gateway, the Scenario Adapter and the skills as
  they are.
- Changing `AGENTS.md` or the skills changes the policy hash recorded in every run
  (`agent_start.run.policy`). Results are then comparable only with runs that share that hash.

The attacker side is independent of this page: the Attack Box sample also uses OpenCode
(see [examples/attacker/README.md](../examples/attacker/README.md)).
