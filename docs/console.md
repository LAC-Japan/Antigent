# Console replay and demo checks

The Console can replay a completed runs layout without starting a target, attacker, or
defender. The Console is display-only: it has no command execution endpoints, and the
container has no Docker socket.

**Language:** English | [日本語](ja/console.md)

## Included synthetic demo

From the extracted distribution root:

```sh
mkdir -p runs
cp -R fixtures/sample-run runs/demo
python server.py --replay --run-dir runs/demo \
  --sensor-log '' --driver-log '' --port 8766
```

Open <http://127.0.0.1:8766>. `--replay` reads existing JSONL records from the
beginning; without it, the Console retains its normal live-tail behavior. `--run-dir`
selects the runs layout used for display, reset, and export. The empty
sensor/driver arguments disable streams that this small fixture does not contain.

The sample data is synthetic and must not be presented as a measured performance
result.

## Containerized replay

1. Copy the fixture to `./runs/demo` on the host.
2. Add these settings to `.env`:

   ```dotenv
   ANTIGENT_RUN_DIR=/console/runs/demo
   ANTIGENT_REPLAY=1
   CONSOLE_PORT=8766
   ```

3. Start only the Console:

   ```sh
   docker compose up -d console
   ```

Return to live mode by removing the replay settings and recreating the Console. Keep
completed-run replay separate from an active experiment's `runs/` directory.

## Completed-run layout

```text
<run-dir>/
  attacker/attacker.jsonl   # optional audience/evaluation stream
  defense/defense.jsonl     # assessments, decisions, actions, observed events
  defense/sensor.jsonl      # optional continuous sensor stream
  defense/driver.jsonl      # optional turn trigger/end stream
  defense/intervention_state.json  # typed-action reservations and evidence links
  defense/driver.finalized.json    # optional final-reobservation receipt
  defense/recovery.json            # optional adapter recovery report
  console/                  # Console-owned session records; created as needed
```

Individual stream paths can be overridden with `--attacker-log`, `--defense-log`,
`--sensor-log`, and `--driver-log`. An explicitly empty value disables that stream.
Equivalent environment variables are documented by `python server.py --help`.
**Export** downloads the merged JSONL streams. Preserve the JSON state, finalization, and
recovery sidecar files with the run directory when a complete typed-action evidence chain
is required; they are not embedded in the JSONL export.

## Reading the Defender view

- Observed telemetry is grouped into collapsible batches; a gap of more than 2 seconds starts
  a new batch, and older batches collapse unless you opened or closed them yourself.
- Antigent's own activity is never folded: turn markers, Antigent's actions and
  `HONEYTOKEN TRIGGERED` lines sit between batches and end the current batch.
- **raw: on/off** hides or shows low-level requests from external clients. Antigent still
  observes them; the toggle only changes the display.
- **N internal** in the title counts traffic between the lab's own services (and the Docker
  host). It is outside Antigent's observation and is never shown.
- When you are at the bottom of a pane it follows new items; when you have scrolled up, the
  position stays where it is.

## Demo acceptance checklist

- All three panes render: **Attacker**, **Defender view**, and **Antigent**.
- Replayed attacker commands and defense assessments/actions appear without a live
  agent.
- Target health comes from the sensor's status file (container state as Docker reports it);
  replay does not make an offline target healthy.
- **Export** downloads JSONL merged from the selected run directory; JSON sidecar files
  remain preserved separately in that directory.
- The UI has no command inputs, and the server has no command endpoints (HTTP 404).
- Starting replay does not create target builds, alter target files, or invoke a model.

For running the demo, see [usage.md](usage.md). To summarise a run: `python3 eval/metrics.py runs/demo`.
