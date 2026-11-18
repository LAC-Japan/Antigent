# Antigent Defense Plane - Usage Guide

This guide walks through the complete setup, execution, and result verification
for the CI/CD Goat Caterpillar demo.

**Language:** English | [日本語](ja/usage.md)

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Running the Demo](#running-the-demo)
4. [Verifying Results](#verifying-results)
5. [Troubleshooting](#troubleshooting)
6. [Advanced Configuration](#advanced-configuration)

---

## Prerequisites

### System Requirements

- **OS**: macOS, Linux, or Windows with WSL2
- **RAM**: 8 GB minimum (16 GB recommended)
- **Disk**: 10 GB free space
- **Docker**: Docker Desktop 4.x+ or Docker Engine 20.10+ with Compose plugin

### Required Software

1. **Docker with Compose**

   Verify installation:
   ```sh
   docker --version
   docker compose version
   ```

2. **uv package manager** (recommended) or Python 3.10+

   Install uv:
   ```sh
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

3. **CI/CD Goat** (target application)

   ```sh
   git clone https://github.com/cider-security-research/cicd-goat.git
   ```

### Model Requirements

The demo uses OpenCode's free models by default (no API key needed). You can also use:

- **OpenAI models** (`openai/*`, API key per role)
- **Amazon Bedrock models** (`amazon-bedrock/*`, credential per role)

> **Data-use note**: with any `opencode/*` model, prompts and tool output
> (including lab secrets such as the challenge flag) are sent to OpenCode's model
> provider. The default `opencode/glm-5.3-flash-free` follows a zero-retention,
> no-training policy, but some other free models may retain data or use it to
> improve the model. Check <https://opencode.ai/docs/zen/#privacy> before choosing
> a model, and never run the demo against real systems or real credentials.
>
> **Usage-limit note**: OpenCode free models have a daily free usage quota. A
> single demo run (a 5-minute autonomous attack plus the defense turns) can
> exhaust it, after which model calls fail with HTTP 429 until the quota resets.
> If the defense plane stops responding or the attacker stops immediately, wait
> for the reset or switch `ATTACKER_MODEL` / `DEFENDER_MODEL` in `.env` to a
> paid/provider-key model.

---

## Environment Setup

### Step 1: Extract the Distribution

```sh
unzip antigent-<version>.zip
cd antigent-<version>
```

### Step 2: Configure Environment

Copy the example environment file:

```sh
cp .env.example .env
```

Edit `.env` with your settings:

```sh
# REQUIRED: Path to your CI/CD Goat checkout
# (default works when you cloned it into the distribution root)
CICD_GOAT_DIR=./cicd-goat

# Model selection (optional, defaults shown)
ATTACKER_MODEL=opencode/glm-5.3-flash-free
DEFENDER_MODEL=opencode/glm-5.3-flash-free

# Console port (optional, default: 8765)
CONSOLE_PORT=8765

# Attack timeout in seconds (optional, default: 1800 = 30 minutes)
ATTACK_TIMEOUT=1800
```

### Step 3: Validate Configuration

Run dry-run to validate without starting containers or calling models:

```sh
uv run python live_demo.py dry-run
```

Expected output:
```
=== Antigent Demo dry-run ===
Run ID: demo
Defense plane: /path/to/antigent
CI/CD Goat: /path/to/cicd-goat

Configuration valid:
  Attacker model: opencode/glm-5.3-flash-free
  Defender model: opencode/glm-5.3-flash-free
  Console port: 8765
  Attack timeout: 1800s

dry-run complete. No containers, volumes, or model calls made.
Run 'uv run python live_demo.py run' to start the demo.
```

---

## Running the Demo

### Start the Demo

```sh
uv run python live_demo.py run
```

The demo will:

1. **Start fresh CI/CD Goat Caterpillar** (~60 seconds)
2. **Build and start Defense Plane** (~120 seconds)
3. **Wait for defense baseline** (~60 seconds)
4. **Start AUTO attacker** (~30 seconds)
5. **Monitor until timeout or completion**

### Expected Output

```
=== Antigent Demo run (demo) ===

[1/5] Starting fresh CI/CD Goat Caterpillar...
  Target started: gitea, jenkins-server, prod

[2/5] Starting Defense Plane...
  Defense ready, Console at http://127.0.0.1:8765
  Jenkins containment ready (logged in as admin, administrator)
  (JENKINS_* unset: "NOTE: Jenkins containment is off ..."; login or permission problem: a WARNING with the reason)

[3/5] Waiting for defense baseline...
  Baseline observation complete

[4/5] Starting AUTO attacker...
  Egress check passed: only the allow-listed LLM API is reachable
  Attacker running (timeout: 1800s)

[5/5] Monitoring attack...
  Console: http://127.0.0.1:8765
  Press Ctrl-C to stop early

  attacker commands: 12 | LLM tunnels: 2 opened (2 open), 0 refused
  ...

Attack timeout reached
  attacker commands: 85 | LLM tunnels: 2 opened (2 open), 0 refused

Draining defense and final reobservation...
  Final reobservation accepted; recovery complete (2 effects)
  # If no typed action changed the target:
  # Final reobservation accepted; no target recovery required

Demo run complete. Console remains at http://127.0.0.1:8765
Run 'uv run python live_demo.py stop' to clean up.
```

### Stop the Demo

```sh
uv run python live_demo.py stop
```

A successful run performs final reobservation and target-native recovery before reporting
completion. `stop` retries any required recovery before stopping the defense plane, skips an
already complete recovery report, and prints a warning if restoration or final containment
verification is incomplete. See `runs/demo/defense/driver.finalized.json` and
`runs/demo/defense/recovery.json`. Recovery completion and containment effectiveness are
separate fields: inspect `containment_final[].status` rather than treating `complete: true`
as proof that containment remained effective.

---

## Verifying Results

### Access the Console

Open your browser to <http://127.0.0.1:8765>.

### Console Layout

The Console has three panes:

| Pane | Content |
|------|---------|
| **Left** | Attacker commands from the Attack Box log (ground truth for evaluation; never shown to Antigent) |
| **Center** | Defense-visible telemetry (logs, file changes, network events) |
| **Right** | Antigent's assessments, decisions, and action results |

### Key Indicators of Successful Defense

1. **Banners in the Defender view** (pinned, never folded):
   - `✓ HONEYTOKEN TRIGGERED · attacker used decoy <marker>` — the attacker used a planted decoy.
   - `⛔ CONTAINMENT VERIFIED · ...` — a containment action was confirmed by independent readback.
2. **Interventions** in the right pane: `Decoy planted` cards and gateway actions with
   `exit 0` and their native receipt.
3. **Attacker behavior** in the left pane: commands that use the decoy value, and attempts
   that stop working after containment.

Each intervention is recorded as separate evidence stages:
`delivered → read → followed / decision changed → reobserved`.

### Export Results

Click **Export** in the Console to download `<session>-merged.jsonl`: one JSON object per
line, from all planes (attacker commands, defender telemetry, Antigent turns, records,
actions and receipts), in time order.

### Reviewing a Finished Run

An export can be opened again later, without Docker, the lab or a model:

```sh
uv run python live_demo.py view ~/Downloads/<session>-merged.jsonl
```

Open <http://127.0.0.1:8766>. The three panes, the banners and the turn markers are rebuilt
from the file; **Export** returns the same file. Use `--port` for another port. Only the
Python standard library is needed (`python3 server.py --import <file> --port 8766` works too).

### Manual Verification

You can also verify results manually:

```sh
# Check defense log
cat runs/demo/defense/defense.jsonl | jq .

# Check attacker log (if available)
cat runs/demo/attacker/attacker.jsonl | jq .

# Verify no containers are left running
docker ps | grep -E "(antigent|gitea|jenkins|prod)"
```

---

## Troubleshooting

### Common Issues

#### 1. Docker daemon not running

**Error**: `Docker daemon not running or not accessible`

**Solution**: Start Docker Desktop or the Docker daemon:
```sh
# macOS
open /Applications/Docker.app

# Linux
sudo systemctl start docker
```

#### 2. CI/CD Goat not found

**Error**: `CICD_GOAT_DIR not found: ./cicd-goat`

**Solution**: Clone CI/CD Goat into the distribution root, or update the path in `.env`:
```sh
git clone https://github.com/cider-security-research/cicd-goat.git
# Or set CICD_GOAT_DIR in .env to the absolute path of your checkout
```

#### 3. Port already in use

**Error**: `port is already allocated` or similar

**Solution**: Change the console port in `.env`:
```sh
CONSOLE_PORT=8766
```

#### 4. Model not available

**Error**: Model API errors or timeouts

**Solution**:
- Verify the model name with `opencode models`
- For OpenAI models, check API key validity
- Try using a different free model (e.g., `opencode/deepseek-v4.1-flash-free`)

#### 5. Defense baseline timeout

**Error**: Defense fails to reach `baseline.ready: true`

**Solution**:
- Ensure target containers are fully started
- Check target logs: `docker logs gitea`, `docker logs jenkins-server`
- Increase `ANTIGENT_WARMUP_TIMEOUT` if needed

### Resetting

If you need to completely reset:

```sh
# Stop everything
uv run python live_demo.py stop

# Remove containers and volumes
docker compose down -v
cd /path/to/cicd-goat && docker compose down -v

# Remove run data
rm -rf runs/demo

# Start fresh
uv run python live_demo.py run
```

---

## Advanced Configuration

### Using OpenAI Models

For better attack and defense performance, use OpenAI GPT-4:

```sh
# In .env
ATTACKER_MODEL=openai/gpt-4o
DEFENDER_MODEL=openai/gpt-4o
OPENAI_ATTACKER_KEY=sk-your-attack-key
OPENAI_DEFENDER_KEY=sk-your-defense-key
```

### Using Amazon Bedrock

```sh
# In .env
ATTACKER_MODEL=amazon-bedrock/global.moonshotai.kimi-k3
DEFENDER_MODEL=amazon-bedrock/global.moonshotai.kimi-k3
ANTIGENT_AWS_REGION=us-east-1                 # used by both roles
ANTIGENT_AWS_BEARER_TOKEN_BEDROCK=...         # defender (or ANTIGENT_AWS_ACCESS_KEY_ID / _SECRET_ACCESS_KEY)
ATTACKER_AWS_BEARER_TOKEN_BEDROCK=...         # attacker's own credential (or ATTACKER_AWS_ACCESS_KEY_ID / ...)
```

Every command the attacker runs can read its credential, so give it its own short-lived,
low-limit one. Reusing the defender's credential is refused unless
`ATTACKER_SHARE_DEFENDER_CREDENTIALS=1`.

### Jenkins Containment

To enable Jenkins job containment (`jenkins_disable_job`), provide the credentials of a Jenkins
administrator of the lab. Only the adapter uses them; the agent has no tool that can read them:

```sh
# In .env
JENKINS_URL=http://host.docker.internal:8080
JENKINS_ADMIN_USER=<lab Jenkins administrator>
JENKINS_ADMIN_PASSWORD=<its password>
```

Without credentials, only Gitea decoy interventions are available.

### Custom Run ID

To run multiple demos without overwriting:

```sh
# In .env
DEMO_RUN_ID=my-test-run
```

Results will be saved to `runs/my-test-run/`.

### Attack Timeout

Adjust the maximum attack duration:

```sh
# In .env (default: 1800 = 30 minutes)
ATTACK_TIMEOUT=3600  # 60 minutes
```

---

## Security Notes

1. **Authorization**: Only use Antigent on systems you are authorized to test.
2. **Production**: Never point Antigent at production systems.
3. **Credentials**: Keep API keys in `.env`, never commit them to version control.
4. **Network**: The attack box has no external network access except to the LLM proxy.
5. **Isolation**: All containers run on a single Docker host with no external exposure.

---

## Next Steps

- **Scenario adapter**: See `docs/cicd-goat.md`
- **Summarising a run**: `python3 eval/metrics.py runs/demo` (detection lag, interventions, honeytoken use; standard library only)
- **Architecture**: See `docs/architecture.md` for system design
- **Security model**: See `docs/security.md` for detailed security boundaries

---

## License

Apache License 2.0. See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
