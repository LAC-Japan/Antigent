"""Antigent event log: plane-separated streams and their merge (v0.12).

The event log is OWNED by the Defense plane (this repo): its location (runs/), its
stream formats and this merge logic. Each producer writes ONLY its own stream, and
no producer reads another's:

  runs/defense/defense.jsonl      Defense Gateway (①②③, action results, markers, run manifests)
  runs/defense/sensor.jsonl       Sensor daemon (v0.14): continuous observed events with level
                                  baseline / raw / elevated
  runs/defense/driver.jsonl       Event-driven driver (v0.14): trigger / turn_end
  runs/attacker/attacker.jsonl    Attack Box command log (attackbox/cmdlog.sh). Optional.
  runs/console/<session>.jsonl    Console session markers

Without an attacker stream, defender-side metrics still work; attacker-side metrics
(attack speed, honeytoken use, error rate) are reported as unavailable.

The Console tails the streams for display; eval/metrics.py merges them directly, so a run
can be summarised without the Console. Standard library only.
"""
import json
import os
import re
import stat
from pathlib import Path


def read_jsonl(path: Path) -> list[dict]:
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        pass
    except OSError:
        pass
    return out


_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def read_output_file(out_dir: Path, raw_id: str, ext: str, limit: int = 200_000) -> tuple[bytes, bool] | None:
    """Read <out_dir>/<id>.<ext> written by the attack plane, safely.

    The id comes from the attacker-writable log, so it must be a plain name (no path
    separators or "..") and the file must be a regular file opened without following a
    symlink; otherwise an attacker could make the Console or an export read any file the
    reader can access (e.g. a host credential when eval runs on the host).
    Returns (data[:limit], truncated) or None."""
    if not _SAFE_ID.match(str(raw_id)) or ".." in str(raw_id):
        return None
    path = Path(out_dir) / f"{raw_id}.{ext}"
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        with os.fdopen(fd, "rb") as f:
            fd = -1
            data = f.read(limit + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    return data[:limit], len(data) > limit


def attacker_command_id(raw_id: str) -> str:
    return "ab-" + str(raw_id)[-12:].replace("-", "")


def attacker_events(lines: list[dict], out_dir: Path | None = None) -> list[dict]:
    """attacker-log JSONL (start/end/cmd) -> unified 'command' events (side=attacker)."""
    cmds: dict[str, dict] = {}
    order = []
    for ev in lines:
        kind, rid = ev.get("event"), str(ev.get("id", ""))
        cid = attacker_command_id(rid)
        ts = float(ev.get("ts") or 0)
        if kind in ("start", "cmd"):
            if cid in cmds:
                continue
            cmds[cid] = {"id": cid, "side": "attacker", "command": ev.get("command", ""), "created": ts,
                         "started": ts, "status": "running" if kind == "start" else "done",
                         "exit_code": ev.get("exit_code"), "duration": 0.0 if kind == "cmd" else None,
                         "via": ev.get("via"), "observed": True, "turn": None, "operator": None,
                         "stdout": "", "stderr": "", "_raw_id": rid}
            order.append(cid)
        elif kind == "end" and cid in cmds:
            c = cmds[cid]
            c["exit_code"], c["status"] = ev.get("exit_code"), "done"
            c["duration"] = round(ts - c["created"], 3)
    for cid in order:
        c = cmds[cid]
        if out_dir is not None:
            for ext, key in (("out", "stdout"), ("err", "stderr")):
                got = read_output_file(out_dir, c["_raw_id"], ext)
                if got is not None:
                    c[key] = got[0].decode("utf-8", "replace")
        c.pop("_raw_id", None)
    return [{"ts": cmds[c]["created"], "type": "command", "plane": "attacker", "command": cmds[c]} for c in order]


def merge(runs: Path, stream_paths: dict[str, str | Path] | None = None) -> list[dict]:
    """All streams under a runs/ folder, merged and sorted by time.

    Console launchers may bind the four producer streams outside their default
    locations. Optional paths follow the actual tail configuration; an empty
    value disables that stream just as it does for the corresponding tailer.
    """
    runs = Path(runs)
    configured = stream_paths or {}

    def stream_path(name: str, default: Path) -> Path | None:
        value = configured.get(name, default)
        return Path(value) if value else None

    events = []
    for name in ("defense", "sensor", "driver"):
        path = stream_path(name, runs / "defense" / f"{name}.jsonl")
        if path is not None:
            events += read_jsonl(path)
    att = stream_path("attacker", runs / "attacker" / "attacker.jsonl")
    if att is not None:
        events += attacker_events(read_jsonl(att), att.parent / "out")
    for f in sorted((runs / "console").glob("*.jsonl")):
        events += read_jsonl(f)
    events.sort(key=lambda e: float(e.get("ts") or 0))
    return events


def sessions(events: list[dict]) -> list[dict]:
    """Session markers written by the Console (New session) or by a harness."""
    return [e for e in events if e.get("type") == "session"]


def with_run_context(all_events: list[dict], selected: list[dict], start: float | None) -> list[dict]:
    """Prepend the latest agent_start (run manifest) that precedes `start`, so a window or a
    Console export always says which policy / model / scenario was running."""
    if start is None or any(e.get("type") == "agent_start" for e in selected):
        return selected
    prior = [e for e in all_events if e.get("type") == "agent_start" and float(e.get("ts") or 0) < start]
    return ([prior[-1]] if prior else []) + selected


def runs_of(events: list[dict]) -> list[dict]:
    """Run manifests (agent_start events) in time order."""
    return [e for e in events if e.get("type") == "agent_start"]


def window(events: list[dict], since: float | None = None, until: float | None = None) -> list[dict]:
    return [e for e in events
            if (since is None or float(e.get("ts") or 0) >= since)
            and (until is None or float(e.get("ts") or 0) < until)]
