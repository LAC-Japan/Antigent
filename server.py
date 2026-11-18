#!/usr/bin/env python3
"""Antigent Console -- display-only viewer for the event log.

Tails the plane-separated streams under runs/ (attacker, defense, sensor, driver) and shows
them in a browser. It executes nothing and has no Docker access: Antigent acts only through
the Defense Gateway, and the attacker plane only writes runs/attacker/. The only state it
writes is its own session marker stream (runs/console/<session>.jsonl, "New session").
The former operator mode (typing attacker/defender commands, holding commands) was removed.

Standard library only (Python 3.10+):
    python server.py                      # -> http://127.0.0.1:8765
    python server.py --replay --run-dir runs/demo   # completed-run replay
"""
import argparse
import json
import os
import queue
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
import sys  # noqa: E402
sys.path.insert(0, str(ROOT / "eval"))
import streams  # noqa: E402  (plane-separated event log, shared with eval/metrics.py)
MAX_OUT = 200_000  # bytes kept per stream

# Scenario Adapter: everything target-specific (label)
# comes from <scenario>/scenario.json -> "console". The console itself is scenario-agnostic.
DEFAULT_SCENARIO = ROOT / "scenarios" / "cicd-goat"


def load_scenario_console(folder: Path) -> dict:
    try:
        sc = json.loads((folder / "scenario.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"[console] scenario not loaded from {folder}: {e}")
        return {"label": folder.name}
    c = sc.get("console", {})
    return {"label": c.get("label", sc.get("name", folder.name))}

DEFAULT_ATTACKER_LOG = ROOT / "runs" / "attacker" / "attacker.jsonl"
DEFAULT_DEFENSE_LOG = ROOT / "runs" / "defense" / "defense.jsonl"
DEFAULT_SENSOR_LOG = ROOT / "runs" / "defense" / "sensor.jsonl"   # v0.14: continuous observation
DEFAULT_DRIVER_LOG = ROOT / "runs" / "defense" / "driver.jsonl"   # v0.14: event-driven turns
MAX_OBSERVED = 600   # observed events kept for the center timeline
MAX_BODY = 1 << 16   # the only POST body is the (empty) New session request
DEFAULT_ALLOWED_HOSTS = ("127.0.0.1", "localhost", "::1")
OUTPUT_SETTLE_SEC = 1.5  # re-read attackbox output files once tee has had time to flush

# Terminal control sequences: CSI (colors, cursor moves), OSC (titles, hyperlinks), and
# the remaining two-byte escapes. Tools run under `tee` or `docker exec` still emit them
# (forced colors, progress bars), and a browser <pre> shows them as garbage.
_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_output(text: str) -> str:
    """Display-only cleanup of captured terminal output (evidence files stay untouched).

    Strips ANSI escapes, resolves carriage-return overwrites the way a terminal would
    (progress bars keep only their final state), applies backspaces, and drops other
    control characters except tab and newline."""
    if not text:
        return text
    text = _ANSI_RE.sub("", text).replace("\r\n", "\n")
    lines = []
    for line in text.split("\n"):
        if "\r" in line:
            parts = [p for p in line.split("\r") if p]
            line = parts[-1] if parts else ""
        if "\b" in line:
            buf: list[str] = []
            for ch in line:
                if ch == "\b":
                    if buf:
                        buf.pop()
                else:
                    buf.append(ch)
            line = "".join(buf)
        lines.append(_CTRL_RE.sub("", line))
    return "\n".join(lines)


def display_command(c: dict) -> dict:
    """Copy of a command record with stdout/stderr cleaned for the browser."""
    c = dict(c)
    for key in ("stdout", "stderr"):
        if isinstance(c.get(key), str):
            c[key] = clean_output(c[key])
    return c


def resolve_run_layout(args):
    """Resolve the selected runs directory and fill only unspecified stream paths."""
    run_dir = Path(args.run_dir)
    if not run_dir.is_absolute():
        run_dir = (ROOT / run_dir).resolve()
    defaults = (
        ("attacker_log", DEFAULT_ATTACKER_LOG),
        ("defense_log", DEFAULT_DEFENSE_LOG),
        ("sensor_log", DEFAULT_SENSOR_LOG),
        ("driver_log", DEFAULT_DRIVER_LOG),
    )
    for name, default in defaults:
        if getattr(args, name) is None:
            setattr(args, name, str(run_dir / default.relative_to(ROOT / "runs")))
    return run_dir


class Hub:
    """In-memory event store + SSE fan-out + JSONL persistence."""

    def __init__(self, run_dir: Path, cfg: dict):
        self.cfg = cfg
        self.lock = threading.Lock()
        self.subs: list[queue.Queue] = []
        self.new_session(run_dir)

    def new_session(self, run_dir: Path):
        with self.lock:
            self.session = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:4]
            self.started = time.time()
            self.commands: dict[str, dict] = {}
            self.records: list[dict] = []
            self.observed: list[dict] = []   # v0.14: defender-side events (center timeline)
            self.triggers: list[dict] = []   # v0.14: driver turn starts / ends
            self.outcomes: list[dict] = []   # native containment results (verified or not)
            self.turn = 0
            run_dir.mkdir(parents=True, exist_ok=True)
            # The console writes ONLY its own session-marker stream. Defense/attacker events
            # are written by their planes and only tailed here for display.
            self.run_dir = run_dir
            (run_dir / "console").mkdir(parents=True, exist_ok=True)
            self.log_path = run_dir / "console" / f"{self.session}.jsonl"
        self.publish({"type": "session", "session": self.session, "started": self.started})

    def publish(self, ev: dict, persist: bool = True, display: dict | None = None):
        """Persist `ev` to the session stream (if asked) and fan out `display` (default:
        the same event) to the browsers, e.g. with terminal output cleaned for display."""
        ev.setdefault("ts", time.time())
        with self.lock:
            if persist:
                ev.setdefault("plane", "console")
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(ev, ensure_ascii=False) + "\n")
            subs = list(self.subs)
        out = ev if display is None else {"ts": ev["ts"], **display}
        for q in subs:
            q.put(out)

    def snapshot(self):
        with self.lock:
            return {
                "session": self.session,
                "started": self.started,
                "turn": self.turn,
                "commands": [display_command(c) for c in
                             sorted(self.commands.values(), key=lambda c: c.get("created") or 0)],
                "records": list(self.records),
                "observed": list(self.observed),
                "triggers": list(self.triggers),
                "outcomes": list(self.outcomes),
                "config": {
                    "scenario": self.cfg.get("scenario", ""),
                    "replay": bool(self.cfg.get("replay")),
                    "imported": self.cfg.get("imported_rows") is not None,
                },
            }

    def emit_cmd(self, cid: str):
        with self.lock:
            c = dict(self.commands[cid])
        # Commands come only from the attacker and defense streams, which already hold
        # them; browsers get cleaned output while those streams keep the raw bytes.
        self.publish({"type": "command", "command": c}, persist=False,
                     display={"type": "command", "command": display_command(c)})

    # --- attacker commands observed in the attackbox (display only) -----------
    def observe_attacker(self, ev: dict, out_dir: Path):
        """One JSONL line from the attackbox shell hook. Agent-agnostic: whatever ran
        the command (Hermes over SSH, another agent, a human) it shows up here. Shown
        to the audience only; never passed to Antigent."""
        lid = str(ev.get("id", ""))
        cid = "ab-" + lid[-12:].replace("-", "")
        kind = ev.get("event")
        if kind in ("start", "cmd"):
            cmd = {"id": cid, "side": "attacker", "command": ev.get("command", ""),
                   "created": float(ev.get("ts") or time.time()), "status": "running",
                   "turn": None, "stdout": "", "stderr": "", "exit_code": None,
                   "duration": None, "operator": None, "via": ev.get("via"), "observed": True}
            with self.lock:
                if cid in self.commands:
                    return
                self.turn += 1
                cmd["turn"] = self.turn
                cmd["started"] = cmd["created"]
                self.commands[cid] = cmd
            if kind == "start":
                self.emit_cmd(cid)
                return
        with self.lock:
            c = self.commands.get(cid)
            if not c:
                return
        with self.lock:
            if kind == "end":
                self._load_attacker_output(c, out_dir, lid)
            c["exit_code"] = ev.get("exit_code")
            c["duration"] = round(float(ev.get("ts") or time.time()) - c["created"], 3)
            c["status"] = "done"
        self.emit_cmd(cid)
        if kind == "end" and not self.cfg.get("replay"):
            # The attackbox writes output through `tee` process substitutions that can
            # finish after the end record. Re-read once later instead of blocking the tailer.
            t = threading.Timer(OUTPUT_SETTLE_SEC, self._refresh_attacker_output, args=(cid, out_dir, lid))
            t.daemon = True
            t.start()

    @staticmethod
    def _load_attacker_output(c: dict, out_dir: Path, lid: str) -> bool:
        """Fill stdout/stderr from <out_dir>/<id>.out|.err; True if anything changed."""
        changed = False
        for ext, key in (("out", "stdout"), ("err", "stderr")):
            got = streams.read_output_file(out_dir, lid, ext, MAX_OUT)   # no traversal / symlinks
            if got is None:
                continue
            data, truncated = got
            text = data.decode("utf-8", "replace")
            if text != c.get(key):
                c[key] = text
                changed = True
            if truncated:
                c["truncated"] = True
        return changed

    def _refresh_attacker_output(self, cid: str, out_dir: Path, lid: str):
        with self.lock:
            c = self.commands.get(cid)
            changed = bool(c) and self._load_attacker_output(c, out_dir, lid)
        if changed:
            self.emit_cmd(cid)

    def ingest_defense(self, ev: dict):
        """One line of runs/defense/defense.jsonl (written by the Defense Gateway): display only."""
        t = ev.get("type")
        if t == "record" and isinstance(ev.get("record"), dict):
            rec = ev["record"]
            with self.lock:
                if any(r.get("id") == rec.get("id") for r in self.records):
                    return
                self.records.append(rec)
            self.publish({"type": "record", "record": rec}, persist=False)
        elif t == "command" and isinstance(ev.get("command"), dict) and ev["command"].get("id"):
            c = dict(ev["command"])
            c.setdefault("created", float(ev.get("ts") or time.time()))
            with self.lock:
                if self.commands.get(c["id"]) == c:
                    return
                # A later line for the same action id (status/result update) replaces the card.
                self.commands[c["id"]] = c
            self.emit_cmd(c["id"])
        elif t == "action_observation" and isinstance(ev.get("observation"), dict):
            # Native containment result (adapter readback): shown as a banner in the Console.
            o = ev["observation"]
            if o.get("record_type") != "containment_observation":
                return
            out = {"action_id": ev.get("action_id") or o.get("action_id"), "status": o.get("status"),
                   "surface": o.get("surface"), "ts": float(ev.get("ts") or time.time())}
            with self.lock:
                if any(x.get("action_id") == out["action_id"] for x in self.outcomes):
                    return
                self.outcomes.append(out)
            self.publish({"type": "containment", "containment": out}, persist=False)
        elif t == "observed":
            # Without a separate sensor daemon the gateway's own observer writes observed
            # events into defense.jsonl (also the documented completed-run layout).
            self.ingest_sensor(ev)

    def ingest_sensor(self, ev: dict):
        """One line of runs/defense/sensor.jsonl (sensor daemon). Baseline events (what
        already existed when sensing started) are not shown."""
        e = ev.get("event")
        if ev.get("type") != "observed" or not isinstance(e, dict) or e.get("level") == "baseline":
            return
        e = {k: v for k, v in e.items() if k not in ("key", "raw")}
        e.setdefault("ts", float(ev.get("ts") or time.time()))
        with self.lock:
            # The same event can arrive from sensor.jsonl and defense.jsonl; keep one.
            if e.get("index") is not None and any(
                    o.get("index") == e["index"] and o.get("source") == e.get("source")
                    for o in self.observed):
                return
            self.observed.append(e)
            if len(self.observed) > MAX_OBSERVED:
                self.observed = self.observed[-MAX_OBSERVED:]
        self.publish({"type": "observed", "event": e}, persist=False)

    def ingest_driver(self, ev: dict):
        """One line of runs/defense/driver.jsonl (event-driven driver)."""
        if ev.get("type") not in ("trigger", "turn_end", "turn_retry", "driver_failed"):
            return
        with self.lock:
            self.triggers.append(ev)
            self.triggers = self.triggers[-200:]
        self.publish({"type": ev["type"], "driver": ev}, persist=False)



def tail_jsonl(path: Path, on_event, replay: bool = False):
    """Follow a JSONL stream, optionally replaying it from the beginning."""
    pos = 0 if replay else (path.stat().st_size if path.exists() else 0)
    buf = b""
    while True:
        try:
            if path.exists():
                size = path.stat().st_size
                if size < pos:
                    pos = 0
                if size > pos:
                    with open(path, "rb") as f:
                        f.seek(pos)
                        buf += f.read()
                        pos = f.tell()
                    *lines, buf = buf.split(b"\n")
                    for line in lines:
                        try:
                            ev = json.loads(line)
                        except ValueError:
                            continue
                        if not isinstance(ev, dict):
                            continue
                        try:
                            on_event(ev)
                        except Exception as e:  # noqa: BLE001
                            # One malformed record must not kill the tailer (the pane would
                            # silently stop updating for the rest of the run).
                            print(f"[console] skipped a record from {path.name}: {e!r}", flush=True)
        except OSError:
            pass
        time.sleep(0.4)


def tail_attacker_log(hub: "Hub", path: Path, replay: bool = False):
    # Process lines in file order on the tailer thread: one thread per line let an `end`
    # overtake its `start` (card stuck at "running") and shuffled the #n numbering.
    tail_jsonl(path, lambda ev: hub.observe_attacker(ev, path.parent / "out"), replay=replay)


def tail_defense_log(hub: "Hub", path: Path, replay: bool = False):
    tail_jsonl(path, hub.ingest_defense, replay=replay)


def tail_sensor_log(hub: "Hub", path: Path, replay: bool = False):
    tail_jsonl(path, hub.ingest_sensor, replay=replay)


def tail_driver_log(hub: "Hub", path: Path, replay: bool = False):
    tail_jsonl(path, hub.ingest_driver, replay=replay)


def sensor_phase(status_path: str | Path | None, max_age: float = 30.0) -> dict:
    """What the defense plane is doing, from the sensor's status file: "off" (no sensor in
    this mode), "starting" (no status yet), "stale" (sensor stopped), "learning" (baseline
    window, events are recorded as baseline and not shown) or "watching"."""
    if not status_path:
        return {"phase": "off"}
    try:
        data = json.loads(Path(status_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"phase": "starting"}
    if time.time() - float(data.get("ts") or 0) > max_age:
        return {"phase": "stale"}
    b = data.get("baseline") or {}
    if b.get("state") == "learning":
        return {"phase": "learning", "elapsed_sec": b.get("elapsed_sec"), "duration_sec": b.get("duration_sec")}
    return {"phase": "watching", "learned": b.get("learned")}


def target_health(status_path: str | Path | None, max_age: float = 30.0) -> list[dict]:
    """Health pills from the sensor's status file (container state read through the Docker
    API guard). The Console itself never connects to a target, so no host address or
    published port is assumed; a stale status (sensor down) shows every target as down."""
    if not status_path:
        return []
    try:
        data = json.loads(Path(status_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    fresh = time.time() - float(data.get("ts") or 0) <= max_age
    return [{"name": t.get("name"), "container": t.get("container"),
             "status": t.get("health") or t.get("state"), "up": bool(t.get("up")) and fresh}
            for t in data.get("targets") or [] if isinstance(t, dict)]


def make_handler(hub: Hub):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, obj, code=200):
            data = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n < 0 or n > MAX_BODY:
                raise ValueError("body too large")
            return json.loads(self.rfile.read(n) or b"{}")

        def _host_ok(self) -> bool:
            """DNS-rebinding guard: the Host header must name this Console."""
            host = (self.headers.get("Host") or "").strip().lower()
            if host.startswith("["):
                name = host[1:].partition("]")[0]
            else:
                name = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
            return name in hub.cfg.get("allowed_hosts", DEFAULT_ALLOWED_HOSTS)

        def _post_ok(self) -> str | None:
            """CSRF guard for state-changing requests. A cross-site page cannot send
            application/json without a CORS preflight (never answered here), and a browser
            always reports a foreign Origin; non-browser clients send no Origin."""
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if ctype != "application/json":
                return "Content-Type must be application/json"
            origin = (self.headers.get("Origin") or "").strip().lower()
            if origin and origin not in ("http://" + (self.headers.get("Host") or "").strip().lower(),):
                return "cross-origin request refused"
            if (self.headers.get("Sec-Fetch-Site") or "").lower() in ("cross-site", "same-site"):
                return "cross-site request refused"
            return None

        def do_GET(self):
            if not self._host_ok():
                return self._json({"error": "unexpected Host header"}, 421)
            if self.path in ("/", "/index.html"):
                data = (ROOT / "static" / "index.html").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)
            elif self.path == "/api/state":
                self._json(hub.snapshot())
            elif self.path == "/api/health":
                sp = hub.cfg.get("status_path")
                self._json({"targets": target_health(sp), "sensor": sensor_phase(sp)})
            elif self.path == "/api/export" and hub.cfg.get("imported_rows") is not None:
                data = "".join(json.dumps(e, ensure_ascii=False) + "\n"
                               for e in hub.cfg["imported_rows"]).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson")
                self.send_header("Content-Disposition", f'attachment; filename="{hub.session}-merged.jsonl"')
                self.end_headers()
                self.wfile.write(data)
            elif self.path == "/api/export":
                # Merged view of this console session across all streams (same as eval sees).
                stream_paths = hub.cfg.get("stream_paths")
                allev = (streams.merge(hub.run_dir, stream_paths=stream_paths)
                         if stream_paths is not None else streams.merge(hub.run_dir))
                # A completed-run replay predates this Console process; export the whole
                # selected run rather than filtering all historical events out by startup time.
                since = None if hub.cfg.get("replay") else hub.started - 0.001
                evs = streams.with_run_context(allev, streams.window(allev, since), since)
                data = "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in evs).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson")
                self.send_header("Content-Disposition", f'attachment; filename="{hub.session}-merged.jsonl"')
                self.end_headers()
                self.wfile.write(data)
            elif self.path == "/api/events":
                q: queue.Queue = queue.Queue()
                with hub.lock:
                    hub.subs.append(q)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("X-Accel-Buffering", "no")  # no proxy buffering of the stream
                self.end_headers()
                try:
                    # Flush something immediately so the browser's `open` fires (it triggers
                    # the state re-sync) even when no event is published for a while.
                    self.wfile.write(b"retry: 2000\n: open\n\n")
                    self.wfile.flush()
                    while True:
                        try:
                            ev = q.get(timeout=15)
                            self.wfile.write(f"data: {json.dumps(ev, ensure_ascii=False)}\n\n".encode())
                        except queue.Empty:
                            self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                finally:
                    with hub.lock:
                        if q in hub.subs:
                            hub.subs.remove(q)
            else:
                self._json({"error": "not found"}, 404)

        def do_POST(self):
            if not self._host_ok():
                return self._json({"error": "unexpected Host header"}, 421)
            refused = self._post_ok()
            if refused:
                return self._json({"error": refused}, 403)
            try:
                b = self._body()
            except Exception:  # noqa: BLE001
                return self._json({"error": "bad json"}, 400)
            if not isinstance(b, dict):
                return self._json({"error": "bad json"}, 400)
            if self.path == "/api/reset":
                if hub.cfg.get("imported_rows") is not None:
                    return self._json({"error": "offline review of an export: nothing to reset"}, 409)
                hub.new_session(hub.run_dir)
                return self._json({"ok": True, "session": hub.session})
            return self._json({"error": "not found"}, 404)

    return H


def import_export(hub: "Hub", path: Path) -> int:
    """Load a Console export (`<session>-merged.jsonl`) into the hub for offline review: the
    same panes, no live streams, no containers. Returns the number of events loaded."""
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if isinstance(ev, dict):
                rows.append(ev)
    rows.sort(key=lambda e: float(e.get("ts") or 0))
    n = 0
    for ev in rows:
        plane, t = ev.get("plane"), ev.get("type")
        if plane == "attacker" and t == "command" and isinstance(ev.get("command"), dict):
            c = dict(ev["command"])
            if c.get("id"):
                with hub.lock:
                    hub.commands[c["id"]] = c
                n += 1
        elif plane == "defense":
            if t == "observed":
                hub.ingest_sensor(ev)
            elif t in ("trigger", "turn_end", "turn_retry", "driver_failed"):
                hub.ingest_driver(ev)
            else:
                hub.ingest_defense(ev)
            n += 1
    hub.cfg["imported_rows"] = rows
    return n


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--import", dest="import_file", default=None, metavar="EXPORT.jsonl",
                    help="review a Console export offline (Export button / *-merged.jsonl); "
                         "no live streams are tailed")
    ap.add_argument("--host", default=os.environ.get("ANTIGENT_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("ANTIGENT_PORT", "8765")))
    ap.add_argument("--scenario", default=os.environ.get("ANTIGENT_SCENARIO", str(DEFAULT_SCENARIO)),
                    help="Scenario Adapter folder (contains scenario.json)")
    ap.add_argument("--run-dir", default=os.environ.get("ANTIGENT_RUN_DIR", str(ROOT / "runs")),
                    help="runs layout for console streams and exports (default: ROOT/runs)")
    ap.add_argument("--replay", action="store_true", default=os.environ.get("ANTIGENT_REPLAY") == "1",
                    help="replay attacker/defense/sensor/driver streams from the beginning")
    ap.add_argument("--allowed-hosts", default=os.environ.get("ANTIGENT_ALLOWED_HOSTS", ""),
                    help="extra Host header names accepted besides 127.0.0.1/localhost/::1 "
                         "(comma list; guards against DNS rebinding)")
    ap.add_argument("--defense-log", default=os.environ.get("ANTIGENT_DEFENSE_LOG"),
                    help="Defense Gateway stream to display in the Defense pane ('' to disable)")
    ap.add_argument("--sensor-log", default=os.environ.get("ANTIGENT_SENSOR_LOG"),
                    help="sensor daemon stream (observed events, center timeline; '' to disable)")
    ap.add_argument("--driver-log", default=os.environ.get("ANTIGENT_DRIVER_LOG"),
                    help="event-driven driver stream (turn markers; '' to disable)")
    ap.add_argument("--attacker-log", default=os.environ.get("ANTIGENT_ATTACKER_LOG"),
                    help="attackbox command log to display in the Attacker pane ('' to disable)")
    a = ap.parse_args()
    if a.import_file:
        # Offline review: nothing is tailed, and the console's own session marker goes to a
        # scratch directory so the imported run's files are never touched.
        import tempfile
        a.run_dir = tempfile.mkdtemp(prefix="antigent-import-")
        a.attacker_log = a.defense_log = a.sensor_log = a.driver_log = ""
        a.replay = True
    run_dir = resolve_run_layout(a)
    sdir = Path(a.scenario)
    if not sdir.is_absolute():
        sdir = (ROOT / sdir).resolve()
    scn = load_scenario_console(sdir)
    cfg = {"scenario": scn["label"],
           "status_path": (str(Path(a.sensor_log).with_name("sensor.status.json"))
                           if a.sensor_log else ""),
           "replay": a.replay,
           "allowed_hosts": DEFAULT_ALLOWED_HOSTS + tuple(
               h.strip().lower() for h in a.allowed_hosts.split(",") if h.strip()),
           "stream_paths": {"attacker": a.attacker_log, "defense": a.defense_log,
                            "sensor": a.sensor_log, "driver": a.driver_log}}
    hub = Hub(run_dir, cfg)
    if a.import_file:
        n = import_export(hub, Path(a.import_file))
        print(f"Imported {n} events from {a.import_file} (offline review, nothing is tailed)")
    if a.attacker_log:
        threading.Thread(target=tail_attacker_log, args=(hub, Path(a.attacker_log), a.replay), daemon=True).start()
    if a.defense_log:
        threading.Thread(target=tail_defense_log, args=(hub, Path(a.defense_log), a.replay), daemon=True).start()
    if a.sensor_log:
        threading.Thread(target=tail_sensor_log, args=(hub, Path(a.sensor_log), a.replay), daemon=True).start()
    if a.driver_log:
        threading.Thread(target=tail_driver_log, args=(hub, Path(a.driver_log), a.replay), daemon=True).start()
    srv = ThreadingHTTPServer((a.host, a.port), make_handler(hub))
    srv.daemon_threads = True
    print(f"Antigent Console  http://{a.host}:{a.port}   session={hub.session}   mode=display-only")
    print(f"  session stream  : {hub.log_path}")
    print(f"  defense stream  : {a.defense_log or '(disabled)'}  (tailed, display only)")
    if a.attacker_log:
        print(f"Attacker pane also shows commands logged by the attackbox: {a.attacker_log}")
    srv.serve_forever()


if __name__ == "__main__":
    main()
