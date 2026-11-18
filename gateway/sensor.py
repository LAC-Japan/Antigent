#!/usr/bin/env python3
"""Antigent sensor daemon (v0.17.0) -- continuous, defender-side observation.

Runs inside the antigent container, next to the driver. Every SENSOR_INTERVAL seconds it
reads the scenario's sensors (docker logs / docker diff of the role containers, through the
socket proxy) with the same Observer the gateway uses, and appends each new event to its
own stream (v0.17: plus the optional netsensor flows, runs/defense/net/flows.jsonl):

  runs/defense/sensor.jsonl     {"ts", "type": "observed", "plane": "defense", "event": {...}}

Each event has a monotonic `index` (its identity, also after restarts) and a `level`:
  baseline   startup / clean-calibration history, or an exact match learned from the
             Scenario Adapter's recurring attacker-free telemetry (not a trigger)
  raw        ordinary telemetry (e.g. one access-log line)
  elevated   a scenario trigger kind (scenario.json "triggers"), e.g. auth-burst,
             fs-change, new-source -- the driver starts an Antigent turn on these

The gateway's observe_events only READS this stream (SENSOR_STREAM). Observation therefore
never depends on whether Antigent is currently running a turn. It never reads the attacker
stream (O1 boundary).

  python3 gateway/sensor.py            # loop
  python3 gateway/sensor.py --once     # one collection cycle (tests)

Config: SENSOR_STREAM (required), SENSOR_INTERVAL (default 2 s), plus the gateway's
ANTIGENT_SCENARIO / DOCKER / <X>_CONTAINER / AUTH_BURST_N / AUTH_WINDOW / OBSERVE_TAIL.
The adapter's `baseline` block owns clean calibration; SENSOR_BASELINE_SEC is an optional
operator override. Standard library only.
"""
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import defense_gateway as gw  # noqa: E402  (scenario, Observer, resolve_container)

STREAM = Path(os.environ.get("SENSOR_STREAM") or (gw.REPO / "runs" / "defense" / "sensor.jsonl"))
STATUS = STREAM.with_name("sensor.status.json")
PROFILE = STREAM.with_name("sensor.baseline.json")
INTERVAL = float(os.environ.get("SENSOR_INTERVAL", "2"))
BASELINE_SEC = float(os.environ.get("SENSOR_BASELINE_SEC")
                     or (gw.SC.get("baseline") or {}).get("duration_sec", 0))
# v0.15.1: filesystem changes on a role within SELF_SETTLE seconds after an Antigent action on
# that role are attributed to Antigent (level raw, cause=antigent) instead of triggering a turn.
SELF_SETTLE = float(os.environ.get("SENSOR_SELF_SETTLE", "15"))


# Upper bound for one typed operation: while an action is running, changes on its role are
# attributed to the defender rather than the attacker.
ACTION_WINDOW = float(os.environ.get("ACTION_TIMEOUT", "60"))


def last_actions() -> dict:
    """role -> end time of the latest Antigent (defender) command, from the defense stream tail."""
    out = {}
    try:
        with open(gw.DEFENSE_LOG, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 262144))
            tail = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return out
    for line in tail:
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        if ev.get("type") == "action_start" and ev.get("role"):   # running: treat as active
            out[ev["role"]] = float(ev.get("ts") or 0) + ACTION_WINDOW
            continue
        c = ev.get("command") if ev.get("type") == "command" else None
        if isinstance(c, dict) and c.get("side") == "defender" and c.get("role"):
            out[c["role"]] = float(c.get("started") or c.get("created") or 0) + float(c.get("duration") or 0)
    return out


def log(*a):
    print("[sensor]", *a, file=sys.stderr, flush=True)


def read_existing() -> list[dict]:
    out = []
    try:
        with open(STREAM, encoding="utf-8") as f:
            for line in f:
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if ev.get("type") == "observed" and isinstance(ev.get("event"), dict):
                    out.append(ev["event"])
    except OSError:
        pass
    return out


def append(ev: dict):
    STREAM.parent.mkdir(parents=True, exist_ok=True)
    with open(STREAM, "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": ev["ts"], "type": "observed", "plane": "defense", "event": ev},
                           ensure_ascii=False) + "\n")


def read_status() -> dict:
    try:
        value = json.loads(STATUS.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def baseline_status(obs: "gw.Observer", learning: bool, started: float | None) -> dict:
    if learning:
        elapsed = max(0.0, time.monotonic() - (started or time.monotonic()))
        return {"ready": False, "state": "learning", "duration_sec": BASELINE_SEC,
                "elapsed_sec": round(elapsed, 1), "learned": 0, "filtered": obs.baseline_filtered}
    if obs.baseline_profile is not None:
        return {"ready": True, "state": "ready", "duration_sec": obs.baseline_profile.duration_sec,
                "learned": len(obs.baseline_profile.entries), "filtered": obs.baseline_filtered,
                "completed_at": obs.baseline_profile.completed_at}
    return {"ready": True, "state": "ready", "duration_sec": 0,
            "learned": 0, "filtered": obs.baseline_filtered}


def save_profile(profile) -> None:
    PROFILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = PROFILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(profile.to_dict(), ensure_ascii=False, indent=2) + "\n")
    os.replace(tmp, PROFILE)


def write_status(obs: "gw.Observer", cycles: int, err: str | None,
                 learning: bool, started: float | None):
    tmp = STATUS.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps({"ts": time.time(), "cycles": cycles, "max_index": obs.next_idx - 1,
                                   "interval": INTERVAL, "scenario": gw.SC.get("name"), "error": err,
                                   "baseline": baseline_status(obs, learning, started),
                                   "targets": obs.target_states(),
                                   "netsensor": ({"stream": str(gw.NET_STREAM), **obs.net_stats}
                                                 if gw.NET_STREAM and gw.NET_STREAM.exists() else None)}))
        os.replace(tmp, STATUS)
    except OSError:
        pass


def main():
    once = "--once" in sys.argv
    existing = read_existing()
    previous_status = read_status()
    obs = gw.Observer(sink=append, start_index=1)
    learning = False
    started = None
    first_cycle = not existing
    if existing:
        obs.restore(existing)
        if PROFILE.exists():
            obs.load_baseline(json.loads(PROFILE.read_text(encoding="utf-8")))
            log(f"loaded clean baseline: {len(obs.baseline_profile.entries)} recurring patterns")
        elif BASELINE_SEC > 0 and (previous_status.get("baseline") or {}).get("state") == "learning":
            # A restart during calibration must not turn an incomplete profile into ready=True.
            # The range has not become ready, so the target must still be attacker-free.
            learning = True
            started = time.monotonic()
            obs.begin_baseline(gw.SC.get("baseline"), BASELINE_SEC)
            log(f"restarting incomplete clean-target baseline for {BASELINE_SEC:.0f}s")
        log(f"resuming {STREAM} at index {obs.next_idx} ({len(existing)} events)")
    elif BASELINE_SEC > 0:
        learning = True
        started = time.monotonic()
        obs.begin_baseline(gw.SC.get("baseline"), BASELINE_SEC)
        log(f"new stream {STREAM}; clean-target baseline for {BASELINE_SEC:.0f}s")
    else:
        obs.baseline = True   # first cycle = what already exists, not activity
        log(f"new stream {STREAM}; first cycle is the baseline")
    roles = list(gw.ROLES)
    log(f"scenario={gw.SC.get('name')} roles={roles} interval={INTERVAL}s "
        f"trigger kinds={sorted(gw.SC['_trigger_kinds'])}")
    cycles = 0
    actions: dict = {}
    obs.self_active = lambda role: time.time() - actions.get(role, 0) <= SELF_SETTLE
    # Persist learning=True before the first collection so even a mid-cycle restart
    # cannot be mistaken for a completed/legacy baseline on the next process start.
    write_status(obs, cycles, None, learning, started)
    while True:
        cycle_start = time.monotonic()
        err = None
        actions = last_actions()
        obs.baseline = first_cycle or learning
        try:
            obs.collect(roles)
        except Exception as e:  # noqa: BLE001 -- keep sensing
            err = str(e)
            log("collect failed:", e)
        if learning and time.monotonic() - started >= BASELINE_SEC:
            profile = obs.finish_baseline()
            save_profile(profile)
            learning = False
            obs.baseline = False
            log(f"clean baseline ready: {len(profile.entries)} recurring patterns; "
                f"{obs.next_idx - 1} events observed")
        elif first_cycle and not learning:
            obs.baseline = False
            log(f"baseline done: {obs.next_idx - 1} events")
        first_cycle = False
        cycles += 1
        write_status(obs, cycles, err, learning, started)
        if once:
            return
        # Fixed cadence: the time spent collecting counts toward the interval, so a request is
        # seen at most about INTERVAL after it appears in a log (not INTERVAL + collect time).
        time.sleep(max(0.0, INTERVAL - (time.monotonic() - cycle_start)))


if __name__ == "__main__":
    main()
