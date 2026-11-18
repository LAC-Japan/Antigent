#!/usr/bin/env python3
"""Antigent Defense Gateway — MCP server (v0.14).

v0.14: observation is CONTINUOUS and owned by the sensor daemon (gateway/sensor.py), which
appends normalised events to runs/defense/sensor.jsonl. With SENSOR_STREAM set, observe_events
only READS that stream (index = position in the stream, so it survives restarts and fresh
`opencode run` sessions started by the event-driven driver, gateway/driver.py).
Each event has a level: "baseline" (already there when sensing started), "raw" (ordinary
telemetry) or "elevated" (scenario trigger kinds: auth-burst, fs-change, new-source, ...);
the driver starts an Antigent turn on elevated events only.


This is the MCP *server*. OpenCode (running Antigent) is the MCP *client* and
launches this process over stdio. Nothing is installed into the target; the gateway
reaches the existing containers from outside through the Docker API (via the
Docker API guard (apiguard/), DOCKER_HOST=tcp://socket-proxy:2375).

The gateway is scenario-agnostic. Everything target-specific (which containers play
which role, which sensors to read, log regexes, the typed operations, context for the agent)
comes from a Scenario Adapter folder: $ANTIGENT_SCENARIO/{scenario.json, adapter.py, context.md}.

Three tools:
  describe_scenario  — roles, sensors and the scenario context (call once at start).
  observe_events     — read defender-side telemetry for the scenario's roles, normalise
                       it into ObservedEvents, return the new ones. Read-only.
  submit_turn        — one defender turn: assessment + decision + at most one typed action.
                       The action is reserved (intervention_gate.py), executed by the
                       scenario adapter, read back natively, and ①②③ and the results are
                       appended to the defense stream.

Event log (v0.11): the gateway writes its own stream, runs/defense/defense.jsonl
(observed events, assessments, decisions, action results, markers). It does not talk
to the console at all. The console tails this file for display; eval/metrics.py reads
it directly, so training/evaluation runs work headless.

Security boundary:
  * The agent never sends a command. It may request only the typed operations its scenario
    adapter declares, on the role each operation belongs to; anything else is refused.
  * Roles resolve to declared containers only (no attackbox, no console, no Antigent itself),
    through the Docker API guard. The console only displays.
  * The antigent container mounts runs/defense only (its own output), never the
    attacker stream.

Transport: newline-delimited JSON-RPC 2.0 on stdin/stdout (MCP stdio transport).
Diagnostics go to stderr only — stdout is the protocol channel.

Standard library only. Config via environment:
  ANTIGENT_SCENARIO  scenario folder (default: <repo>/scenarios/cicd-goat)
  DEFENSE_LOG        default <repo>/runs/defense/defense.jsonl
  DOCKER             default "docker"
  OBSERVE_TAIL       log lines to scan per source on first poll (default 200)
  AUTH_BURST_N / AUTH_WINDOW   burst aggregation (default 5 in 60 s)
  <X>_CONTAINER      referenced from scenario.json as ${X_CONTAINER:-default}
"""
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

from baseline import CleanBaseline
from intervention_gate import CONTEXT_PROTOCOL_ID, InterventionGate

PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "antigent-defense-gateway", "version": "0.1.0"}

REPO = Path(__file__).resolve().parent.parent
SCENARIO_DIR = Path(os.environ.get("ANTIGENT_SCENARIO") or (REPO / "scenarios" / "cicd-goat"))
if not SCENARIO_DIR.is_absolute():
    SCENARIO_DIR = (REPO / SCENARIO_DIR).resolve()
DEFENSE_LOG = Path(os.environ.get("DEFENSE_LOG") or (REPO / "runs" / "defense" / "defense.jsonl"))
DOCKER = os.environ.get("DOCKER", "docker")
OBSERVE_TAIL = int(os.environ.get("OBSERVE_TAIL", "200"))
INTERNAL_REFRESH = float(os.environ.get("INTERNAL_REFRESH", "60"))
NET_REMAP_MIN = float(os.environ.get("NET_REMAP_MIN", "5"))   # rebuild the target map on an unknown address
# Extra addresses to treat as the Docker host (comma list; default none). The target
# networks' gateways are found at run time. Set this only if you browse the lab from the host
# on Docker Desktop (host traffic appears from its VM address) and do not want that seen as a
# client. Antigent's own requests through the host need no entry: see SELF_MARK.
HOST_ADDRESSES = {a.strip() for a in os.environ.get("ANTIGENT_HOST_ADDRESSES", "").split(",") if a.strip()}
# Per-run random value that Antigent's own HTTP clients (the scenario adapter's Jenkins client,
# the demo's Jenkins pre-flight) add as `antigent_self=<mark>`. A request carrying it proves its
# source address is Antigent itself, which is then treated as internal. The attacker never sees
# the value, so it cannot hide its own traffic this way. Empty = feature off.
SELF_MARK = os.environ.get("ANTIGENT_SELF_MARK", "").strip()
SELF_MARK_RE = re.compile(r"[?&]antigent_self=" + re.escape(SELF_MARK) + r"(?:&|$)") if SELF_MARK else None
AUTH_BURST_N = int(os.environ.get("AUTH_BURST_N", "5"))
AUTH_WINDOW = float(os.environ.get("AUTH_WINDOW", "60"))
# v0.15: generic reconnaissance signals per client address (needs log_rules.client with `ip`;
# `status` optional). recon-burst = many requests, error-burst = many 4xx (except 401, which
# is auth-failure), both within RECON_WINDOW seconds.
RECON_WINDOW = float(os.environ.get("RECON_WINDOW", "30"))
RECON_N = int(os.environ.get("RECON_N", "10"))
ERROR_N = int(os.environ.get("ERROR_N", "5"))
MAX_OUT = 20_000
# v0.14: continuous sensing. When set, observe_events reads this stream (written by sensor.py).
SENSOR_STREAM = Path(os.environ["SENSOR_STREAM"]) if os.environ.get("SENSOR_STREAM") else None
# Turn number given by the event-driven driver (gateway/driver.py) to this `opencode run`.
# v0.17: optional network tap (gateway/netsensor.py, compose profile "netsensor"). Its flow
# records are read by the sensor daemon only; absent file = netsensor not running (no-op).
NET_STREAM = Path(os.environ["NET_STREAM"]) if os.environ.get("NET_STREAM") else (
    SENSOR_STREAM.parent / "net" / "flows.jsonl" if SENSOR_STREAM else None)
NET_KEEP_INTERNAL = os.environ.get("NET_KEEP_INTERNAL", "0") == "1"   # internal<->internal flows
NET_DUP = os.environ.get("NET_DUP", "skip")   # skip = no net-http events where an access log exists
NET_MAX_READ = 4 * 1024 * 1024
DRIVER_TURN = int(os.environ["ANTIGENT_DRIVER_TURN"]) if os.environ.get("ANTIGENT_DRIVER_TURN", "").isdigit() else None
DRIVER_REASON = os.environ.get("ANTIGENT_DRIVER_REASON", "")
REOBSERVE_ACTION_IDS = [x for x in os.environ.get("ANTIGENT_REOBSERVE_ACTIONS", "").split(",") if x]
READONLY_REASONS = {"reobservation", "final_reobservation"}
# The only action protocol: typed operations from the scenario adapter, one per observation,
# each reserved persistently and re-observed (see intervention_gate.py).
PROTOCOL_ID = CONTEXT_PROTOCOL_ID
_GATE = None


def gate() -> InterventionGate:
    """Created on first use: the sensor daemon imports this module but never submits."""
    global _GATE
    if _GATE is None:
        _GATE = InterventionGate(DEFENSE_LOG.parent / "intervention_state.json",
                                 defense_log=DEFENSE_LOG, target_fields=lambda: typed_target_fields())
        _GATE.initialize()
    return _GATE


def log(*a):
    print("[defense-gateway]", *a, file=sys.stderr, flush=True)


def emit(ev: dict):
    """Append one event to the defense stream (one JSON object per line)."""
    ev.setdefault("ts", time.time())
    ev.setdefault("plane", "defense")
    try:
        DEFENSE_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(DEFENSE_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    except OSError as e:
        log(f"cannot write {DEFENSE_LOG}: {e}")


def emit_record(kind: str, body: dict) -> dict:
    rec = {"id": uuid.uuid4().hex[:10], "kind": kind, "created": time.time(), **body}
    if DRIVER_TURN is not None:
        rec.setdefault("turn", DRIVER_TURN)
    emit({"type": "record", "record": rec})
    return rec


# --------------------------------------------------------------------------- #
# Scenario Adapter
# --------------------------------------------------------------------------- #
_ENV_RE = re.compile(r"\$\{(\w+)(?::-([^}]*))?\}")


def _expand(v: str) -> str:
    return _ENV_RE.sub(lambda m: os.environ.get(m.group(1)) or (m.group(2) or ""), v)


def load_scenario(folder: Path) -> dict:
    sc = json.loads((folder / "scenario.json").read_text(encoding="utf-8"))
    for role, spec in sc.get("roles", {}).items():
        spec["container"] = _expand(spec.get("container", role))
    ctx = folder / "context.md"
    sc["_context"] = ctx.read_text(encoding="utf-8") if ctx.exists() else ""
    rules = sc.get("log_rules", {})
    sc["_auth_fail"] = [re.compile(r) for r in rules.get("auth_fail", [])]
    sc["_auth_dup"] = [re.compile(r) for r in rules.get("auth_dup", [])]
    sc["_noise"] = [re.compile(r) for r in rules.get("noise", [])]
    # v0.14: regexes with a named group `ip` on ordinary log lines -> "new-source" events.
    sc["_client"] = [re.compile(r) for r in rules.get("client", [])]
    # v0.15.1: response lines without the client address (path + status); the address is taken
    # from the latest request line for the same path (e.g. Gitea "Started ..." / "Completed ...").
    sc["_status"] = [re.compile(r) for r in rules.get("status", [])]
    # v0.15.1: lines used for tracking only (new-source / bursts), not emitted as events.
    sc["_quiet"] = [re.compile(r) for r in rules.get("quiet", [])]
    for spec in sc.get("roles", {}).values():
        for sensor in spec.get("sensors", []):
            sensor["_ignore"] = [re.compile(r) for r in sensor.get("ignore", [])]
            # Lines of an `internal` log that are nevertheless defender telemetry (e.g. a CI run
            # of untrusted code): emitted as `kind`, not internal. Named groups become fields.
            sensor["_surface"] = [(re.compile(r["pattern"]), r.get("kind", "surfaced"))
                                  for r in sensor.get("surface", [])]
    # Request classes (scenario-defined, core default: none): a request from an outside client
    # whose method/path matches is also reported as its own event `kind` (e.g. a repository
    # clone), so the scenario can make it start a turn via triggers.kinds. A named group
    # `target` in `path` says what one event stands for (deduplicated per client and target).
    # Works for requests seen in access logs and by the netsensor alike.
    sc["_request_rules"] = [{"kind": r["kind"], "path": re.compile(r["path"]),
                             "method": (r.get("method") or "").upper() or None,
                             "label": r.get("label") or r["kind"]}
                            for r in sc.get("request_rules", [])]
    # v0.14: which event kinds are "elevated" (start an Antigent turn in driver mode).
    sc["_trigger_kinds"] = set(sc.get("triggers", {}).get(
        "kinds", ["auth-burst", "auth-failure", "fs-change", "new-source", "recon-burst", "error-burst"]))
    return sc


SC = load_scenario(SCENARIO_DIR)
ROLES: dict = SC.get("roles", {})


# Loose coupling: resolve a role's configured container name to a running container.
# Exact match wins; otherwise one whose name CONTAINS it ("gitea" -> "cicd-goat-gitea-1").
_RESOLVE_CACHE: dict[str, str] = {}


def resolve_container(name: str) -> str:
    if not name or name in _RESOLVE_CACHE:
        return _RESOLVE_CACHE.get(name, name)
    try:
        p = subprocess.run([DOCKER, "ps", "--format", "{{.Names}}"],
                           capture_output=True, text=True, timeout=10)
        running = [n for n in p.stdout.split() if n]
    except Exception:  # noqa: BLE001
        running = []
    match = name
    if name not in running:
        # Partial match only when it is unambiguous. Picking the shortest of several names
        # containing e.g. "prod" could aim root `docker exec` at an unrelated container on
        # the same Docker host. Ambiguity resolves to the literal name (which then fails).
        cands = [n for n in running if name in n]
        if len(cands) == 1:
            match = cands[0]
            log(f"resolved target '{name}' -> '{match}'")
        elif cands:
            log(f"target '{name}' is ambiguous ({', '.join(sorted(cands))}); set the exact "
                "container name in the scenario environment")
    if running:  # only cache a real lookup
        _RESOLVE_CACHE[name] = match
    return match


def exec_roles() -> list[str]:
    return [r for r, s in ROLES.items() if s.get("exec", False)]


# Containers of the Antigent planes themselves (defense, socket-proxy, attackbox) are never
# valid action targets, even if a role name happens to resolve to one of them.
EXEC_DENY_PREFIXES = tuple(p for p in os.environ.get("ANTIGENT_EXEC_DENY", "antigent-").split(",") if p)


def role_container(role: str) -> str:
    """Allow-list: only roles declared in the scenario with exec enabled."""
    spec = ROLES.get(role)
    if not spec:
        raise PermissionError(f"unknown role '{role}' (allowed: {', '.join(exec_roles())})")
    if not spec.get("exec", False):
        raise PermissionError(f"role '{role}' is observe-only in this scenario")
    container = resolve_container(spec["container"])
    if container.startswith(EXEC_DENY_PREFIXES):
        raise PermissionError(f"role '{role}' resolved to '{container}', which is an Antigent plane container")
    return container


# --------------------------------------------------------------------------- #
# Observation
# --------------------------------------------------------------------------- #
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def _log_time(stamp: str) -> float | None:
    """`docker logs -t` prefix (RFC 3339, up to ns) -> unix seconds."""
    try:
        from datetime import datetime
        st = stamp.rstrip("Z")
        if "." in st:
            head, frac = st.split(".", 1)
            st = f"{head}.{frac[:6]}"
        return datetime.fromisoformat(st + "+00:00").timestamp()
    except ValueError:
        return None


class Observer:
    """Collects ObservedEvents from the scenario's sensors. Dedups across calls so
    each log line / fs-change is reported once.

    sink:     where each new event goes. Default (inline mode): the defense stream.
              The sensor daemon passes its own sink (runs/defense/sensor.jsonl).
    baseline: while True, events are tagged level="baseline" (what already existed when
              sensing started: old log lines, the container's existing docker diff)."""

    def __init__(self, sink=None, start_index: int = 1):
        self.events: list[dict] = []
        self.seen: set[str] = set()
        self.next_idx = start_index
        self.last_poll: dict[str, float] = {}
        self.fail: dict[tuple, list] = {}
        self.last_user: dict[str, str] = {}
        self.sources: set[tuple] = set()
        self.req: dict[tuple, list] = {}   # (source, ip) -> [(t, path)]: all requests (recon-burst)
        self.err: dict[tuple, list] = {}   # (source, ip) -> [(t, path)]: 4xx except 401 (error-burst)
        self._internal: set[str] = set()
        self._internal_at = 0.0
        self.self_addresses: set[str] = set()   # learned from this run's self-mark (learn_self)
        self.primed: set[tuple] = set()   # (sensor type, container) read successfully at least once
        self.last_ip: dict[tuple, str] = {}   # (source, path) -> ip of the latest request line
        self.self_active = lambda role: False   # sensor: True right after an Antigent action on role
        self.baseline = False
        self.calibration: CleanBaseline | None = None
        self.baseline_profile: CleanBaseline | None = None
        self.baseline_filtered = 0
        self.resume_after: float | None = None   # set by restore(): skip log lines already processed
        self.sink = sink or (lambda ev: emit({"type": "observed", "event": ev}))
        # v0.17 netsensor: file offset, dst address -> source name, roles whose own logs
        # already name clients (net-http there would duplicate the access log), counters.
        self.net_off: int | None = None
        self._net_map: dict[str, str] = {}
        self._net_unmapped: set[str] = set()   # looked up, not a target (until the next refresh)
        self._gw: set[str] = set()
        self._states: list[dict] = []
        self._net_map_at = 0.0
        self.log_client_roles: set[str] = set()
        self.net_stats = {"records": 0, "events": 0, "untargeted": 0, "internal": 0, "dup": 0}

    def begin_baseline(self, config: dict | None, duration_sec: float,
                       started_at: float | None = None) -> None:
        self.calibration = CleanBaseline(config, duration_sec=duration_sec, started_at=started_at)
        self.baseline_profile = None

    def finish_baseline(self, completed_at: float | None = None) -> CleanBaseline:
        if self.calibration is None:
            raise RuntimeError("clean baseline calibration is not active")
        self.baseline_profile = self.calibration.finish(completed_at)
        self.calibration = None
        for entry in self.baseline_profile.entries:
            client = entry["attributes"].get("client")
            if client:
                self.sources.add((entry["source"], client))
        # Requests and failures observed during calibration must not combine with
        # post-calibration traffic to create a burst across the readiness boundary.
        self.req.clear()
        self.err.clear()
        self.fail.clear()
        return self.baseline_profile

    def load_baseline(self, data: dict) -> None:
        self.baseline_profile = CleanBaseline.from_dict(data)
        self.calibration = None
        for entry in self.baseline_profile.entries:
            client = entry["attributes"].get("client")
            if client:
                self.sources.add((entry["source"], client))

    def matches_baseline(self, source: str, kind: str, attrs: dict) -> bool:
        if self.baseline_profile and self.baseline_profile.matches(source, kind, attrs):
            self.baseline_filtered += 1
            return True
        return False

    def restore(self, events: list[dict]):
        """Resume after a restart from an existing stream: dedup keys, next index, known
        sources, and 'logs since' = the newest event time."""
        for ev in events:
            if ev.get("key"):
                self.seen.add(ev["key"])
            if ev.get("ip"):   # new-source and auth events both name the client
                self.sources.add((ev.get("source"), ev["ip"]))
            if ev.get("client") and ev.get("via") != "netsensor":
                self.log_client_roles.add(ev.get("source"))
            self.next_idx = max(self.next_idx, int(ev.get("index", 0)) + 1)
        if events:
            last = max(float(e.get("ts") or 0) for e in events)
            self.resume_after = last
            for spec in ROLES.values():
                c = resolve_container(spec["container"])
                self.last_poll[c] = last
                for sensor in spec.get("sensors", []):
                    self.primed.add((sensor.get("type"), c))

    def level(self, kind: str, force: str | None = None) -> str:
        if self.baseline:
            return "baseline"
        if force:
            return force
        return "elevated" if kind in SC["_trigger_kinds"] else "raw"

    def _add(self, source, kind, summary, raw="", dedup_key=None, level=None, **extra):
        key = dedup_key or hashlib.sha1(f"{source}|{kind}|{summary}".encode()).hexdigest()
        if key in self.seen:
            return
        self.seen.add(key)
        ev = {"index": self.next_idx, "ts": round(time.time(), 3), "source": source,
              "kind": kind, "level": self.level(kind, level), "summary": summary[:500],
              **({"raw": raw[:2000]} if raw and raw.strip() != summary.strip() else {}),
              "key": key, **extra}
        self.events.append(ev)
        self.next_idx += 1
        self.sink(ev)
        if self.calibration is not None:
            self.calibration.observe(ev)
        if len(self.events) > 2000:
            self.events = self.events[-2000:]

    def _docker(self, args, timeout=15):
        p = subprocess.run([DOCKER, *args], capture_output=True, timeout=timeout, text=True)
        return p.returncode, p.stdout, p.stderr

    def collect(self, roles: list[str]):
        """One sensing cycle. The first successful read of each sensor is its baseline, also when
        it happens after the global baseline cycle (e.g. a container that was down or not yet
        resolvable at start), so old log lines / existing changes never start a turn."""
        for role in roles:
            spec = ROLES.get(role)
            if not spec:
                continue
            container = resolve_container(spec["container"])
            for sensor in spec.get("sensors", []):
                t = sensor.get("type")
                sid = (t, container)
                fresh = sid not in self.primed
                prev = self.baseline
                self.baseline = prev or fresh
                try:
                    if t == "docker_logs":
                        ok = self._collect_logs(role, container, sensor.get("kind", "log"),
                                                internal=bool(sensor.get("internal", False)),
                                                surface=sensor.get("_surface", []))
                    elif t == "docker_diff":
                        ok = self._collect_diff(role, container, sensor.get("kind", "fs-change"),
                                                sensor.get("_ignore", []))
                    else:
                        self._add(role, "error", f"unknown sensor type '{t}'")
                        ok = False
                    if ok:
                        self.primed.add(sid)
                    if fresh and ok:
                        # pending auth failures and burst windows from old lines stay baseline
                        self._flush_auth(force=True, source=role)
                        for store in (self.req, self.err):
                            for k in [k for k in store if k[0] == role]:
                                del store[k]
                finally:
                    self.baseline = prev
        self._collect_net()
        self._flush_auth()

    def _collect_logs(self, source, container, kind, internal=False, surface=()):
        try:
            args = ["logs", "-t"]
            since = self.last_poll.get(container)
            args += ["--since", f"{since - 5:.3f}"] if since else ["--tail", str(OBSERVE_TAIL)]
            now = time.time()
            code, out, err = self._docker(args + [container])
            if code != 0:
                self._add(source, "error", f"docker logs {container} failed: {err.strip()[:200]}")
                return False
            self.last_poll[container] = now
            for raw in (out + err).splitlines():
                raw = raw.rstrip()
                if not raw:
                    continue
                stamp, _, line = raw.partition(" ")
                line = strip_ansi(line)
                if not line.strip() or any(r.search(line) for r in SC["_noise"]):
                    continue
                if self.resume_after is not None:
                    lt = _log_time(stamp)
                    if lt is not None and lt <= self.resume_after:
                        continue   # processed before a restart (incl. auth lines inside an emitted burst)
                key = hashlib.sha1(f"{source}|{raw}".encode()).hexdigest()
                if key in self.seen:
                    continue
                if self._auth_line(source, line):
                    self.seen.add(key)
                    continue
                extra = {}
                hit = next(((m, k) for r, k in surface for m in [r.search(line)] if m), None)
                if internal and hit:
                    m, surfaced_kind = hit
                    self._add(source, surfaced_kind, line.strip(), dedup_key=key,
                              **{k: v for k, v in m.groupdict().items() if v})
                    continue
                if internal:
                    extra["internal"] = True   # service's own operational log (e.g. CI build/index)
                else:
                    meta = self._request_meta(source, line)
                    attrs = {"client": meta.get("ip"), "method": meta.get("method"),
                             "path": meta.get("path")}
                    if self.matches_baseline(source, kind, attrs):
                        # Learned periodic activity is retained as baseline evidence, but must not
                        # feed new-source / burst windows or the driver's activity tier.
                        if meta.get("ip"):
                            self.sources.add((source, meta["ip"]))
                            self.log_client_roles.add(source)
                        if meta.get("path") and meta.get("ip"):
                            # A quiet Started line supplies the client to its Completed pair.
                            self.last_ip[(source, meta["path"])] = meta["ip"]
                        if any(r.search(line) for r in SC["_quiet"]):
                            self.seen.add(key)   # quiet request-start lines remain quiet
                        else:
                            self._add(source, kind, line.strip(), dedup_key=key, level="baseline",
                                      baseline_reason="clean_calibration",
                                      **{k: v for k, v in attrs.items() if v})
                        continue
                    client = self._new_source(source, line, _log_time(stamp), meta=meta)
                    if any(r.search(line) for r in SC["_quiet"]):
                        self.seen.add(key)   # tracked (client address, bursts), not shown as an event
                        continue
                    # v0.15.6: `client` = the request's address (if the line has one); internal = the
                    # target's own service. The driver's activity tier counts only external clients.
                    if client:
                        extra["client"] = client
                        if self.is_internal(client):
                            extra["internal"] = True
                    extra.update({k: meta[k] for k in ("method", "path") if meta.get(k)})
                self._add(source, kind, line.strip(), dedup_key=key, **extra)
            return True
        except Exception as e:  # noqa: BLE001
            self._add(source, "error", f"{source} unreadable: {e}")
            return False

    def is_internal(self, ip: str | None) -> bool:
        """Internal = the target's own services (internal_ips) or loopback: a request from
        127.0.0.0/8 or ::1 in a container's access log comes from inside that container
        (setup scripts, health checks, git hooks), never from a remote client."""
        if not ip:
            return False
        ip = ip.strip("[]")
        try:
            if ipaddress.ip_address(ip).is_loopback:
                return True
        except ValueError:
            pass
        return (ip in HOST_ADDRESSES or ip in self.self_addresses
                or ip in self.host_gateways() or ip in self.internal_ips())

    def learn_self(self, ip: str | None, path: str | None) -> bool:
        """Record `ip` as Antigent's own address when the request carries this run's self-mark."""
        if not (SELF_MARK_RE and ip and path and SELF_MARK_RE.search(path)):
            return False
        ip = ip.strip("[]")
        if ip not in self.self_addresses:
            self.self_addresses.add(ip)
            log(f"own requests come from {ip}: treated as internal")
        return True

    def target_states(self) -> list[dict]:
        """Container state of every role (for the Console's health pills), via the Docker API
        guard: no network probe, so no host addresses or published ports are assumed."""
        now = time.time()
        if now - getattr(self, "_states_at", 0.0) < 10:
            return self._states
        self._states_at = now
        out = []
        for role, spec in ROLES.items():
            name = resolve_container(spec["container"])
            code, o, _ = self._docker(["inspect", "-f",
                                       "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}",
                                       name], timeout=10)
            state, _, health = (o.strip().partition(" ") if code == 0 else ("missing", "", ""))
            out.append({"name": role, "container": name, "state": state, "health": health or None,
                        "up": state == "running" and health in ("", "healthy")})
        self._states = out
        return out

    def host_gateways(self) -> set[str]:
        """Gateways of the role containers' networks (= the Docker host on Linux). Networks
        without a host address (the Attack Box lab network) have none."""
        now = time.time()
        if now - getattr(self, "_gw_at", 0.0) < INTERNAL_REFRESH:
            return self._gw
        self._gw_at = now
        gws: set[str] = set()
        for spec in ROLES.values():
            code, out, _ = self._docker(["inspect", "-f", "{{range .NetworkSettings.Networks}}{{.Gateway}} {{end}}",
                                         resolve_container(spec["container"])], timeout=10)
            if code == 0:
                gws.update(x for x in out.split() if x and x != "<no")
        self._gw = gws
        return gws

    def internal_ips(self) -> set[str]:
        """v0.15.4: addresses of the target's own services (e.g. Jenkins scanning Gitea), which
        are not clients to watch. Defined by the Scenario Adapter only (core default: none):
        "internal": {"same_project": true} = every container in the role containers. compose project, plus
        "internal": {"ips": [...]}. Refreshed every INTERNAL_REFRESH s."""
        cfg = SC.get("internal") or {}
        now = time.time()
        if now - self._internal_at < INTERNAL_REFRESH:
            return self._internal
        self._internal_at = now
        ips = {str(x) for x in cfg.get("ips", [])}
        if cfg.get("same_project", False):
            try:
                projects = set()
                for spec in ROLES.values():
                    code, out, _ = self._docker(["inspect", "-f",
                                                 '{{index .Config.Labels "com.docker.compose.project"}}',
                                                 resolve_container(spec["container"])], timeout=10)
                    if code == 0 and out.strip() and out.strip() != "<no value>":
                        projects.add(out.strip())
                for proj in projects:
                    code, out, _ = self._docker(["ps", "-q", "--filter", f"label=com.docker.compose.project={proj}"],
                                                timeout=10)
                    ids = out.split() if code == 0 else []
                    if ids:
                        code, out, _ = self._docker(["inspect", "-f",
                                                     "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", *ids],
                                                    timeout=10)
                        if code == 0:
                            ips.update(x for x in out.split() if x)
            except Exception:  # noqa: BLE001 -- keep the previous set
                return self._internal
        if ips != self._internal:
            log(f"internal sources (not watched as clients): {sorted(ips)}")
        self._internal = ips
        return ips

    def _request_meta(self, source, line) -> dict:
        """Normalise the adapter's client/status rules for burst detection and baseline matching."""
        for r in SC["_client"]:
            m = r.search(line)
            if m and m.groupdict().get("ip"):
                g = m.groupdict()
                return {"ip": g["ip"].strip("[]"), "method": g.get("method"),
                        "path": g.get("path"), "status": g.get("status")}
        for r in SC["_status"]:
            m = r.search(line)
            if m:
                g = m.groupdict()
                ip = self.last_ip.get((source, g.get("path")))
                if ip:
                    return {"ip": ip, "method": g.get("method"),
                            "path": g.get("path"), "status": g.get("status")}
        return {}

    REQUEST_RULE_WINDOW = 30.0   # one event per (role, client, kind, path) in this many seconds

    def _request_rules(self, source, ip, method, path, t=None):
        """Report an outside client's request that matches a scenario request rule."""
        if not (ip and path):
            return
        t = t or time.time()
        for rule in SC.get("_request_rules", []):
            if rule["method"] and (method or "").upper() != rule["method"]:
                continue
            m = rule["path"].search(path)
            if not m:
                continue
            base = path.split("?", 1)[0]
            target = m.groupdict().get("target") or base   # what one event stands for
            bucket = int(t // self.REQUEST_RULE_WINDOW)
            self._add(source, rule["kind"], f"{rule['label']}: {(method or '?').upper()} {base} from {ip} on {source}",
                      dedup_key=f"rr|{source}|{ip}|{rule['label']}|{target}|{bucket}",
                      client=ip, path=base, target=target, **({"method": method.upper()} if method else {}))
            return

    def _new_source(self, source, line, t=None, meta=None):
        """Per client address on a role: first request -> 'new-source'; many requests or many
        4xx within RECON_WINDOW -> 'recon-burst' / 'error-burst' (generic enumeration signals).
        Requests from the target's own services (internal_ips) are logged as raw only."""
        g = self._request_meta(source, line) if meta is None else meta
        if not g:
            return None
        ip = g["ip"]
        self.log_client_roles.add(source)
        self.learn_self(ip, g.get("path"))
        if self.is_internal(ip):
            if g.get("path"):
                self.last_ip[(source, g["path"])] = ip
            return ip
        if (source, ip) not in self.sources:
            self.sources.add((source, ip))
            self._add(source, "new-source", f"first request from {ip} on {source}", line[:500],
                      dedup_key=f"src|{source}|{ip}", ip=ip)
        if g.get("path"):
            self.last_ip[(source, g["path"])] = ip
            if not self.baseline:
                self._request_rules(source, ip, g.get("method"), g["path"], t)
        if g.get("status"):
            # Adapter `client` rules already count the request; `status` rules are the second half
            # of a request pair and contribute only its response status.
            count_request = any(r.search(line) for r in SC["_client"])
            self._activity(source, ip, g["status"], g.get("path"), t or time.time(),
                           count_request=count_request)
        elif any(r.search(line) for r in SC["_client"]):
            self._activity(source, ip, None, g.get("path"), t or time.time(), count_request=True)
        return ip

    # ----------------------------------------------------------------- netsensor (v0.17)
    def net_targets(self, force: bool = False) -> dict[str, str]:
        """Destination address -> source name: the role containers (role name) and the other
        containers of their compose project (service name, observe-only). Generic: derived from
        scenario.json roles + Docker labels, nothing scenario-specific. Refreshed like internal_ips."""
        now = time.time()
        if self._net_map and now - self._net_map_at < INTERNAL_REFRESH and not force:
            return self._net_map
        self._net_map_at = now
        fmt = ('{{.Name}}|{{index .Config.Labels "com.docker.compose.project"}}|'
               '{{index .Config.Labels "com.docker.compose.service"}}|'
               '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}')
        out: dict[str, str] = {}
        try:
            projects = set()
            for role, spec in ROLES.items():
                code, txt, _ = self._docker(["inspect", "-f", fmt, resolve_container(spec["container"])], timeout=10)
                if code != 0 or not txt.strip():
                    continue
                _name, proj, _svc, ips = (txt.strip().split("|") + ["", "", "", ""])[:4]
                for ip in ips.split():
                    out[ip] = role
                if proj and proj != "<no value>":
                    projects.add(proj)
            for proj in projects:
                code, txt, _ = self._docker(["ps", "-q", "--filter", f"label=com.docker.compose.project={proj}"],
                                            timeout=10)
                ids = txt.split() if code == 0 else []
                if not ids:
                    continue
                code, txt, _ = self._docker(["inspect", "-f", fmt, *ids], timeout=10)
                for line in txt.splitlines() if code == 0 else []:
                    name, _p, svc, ips = (line.strip().split("|") + ["", "", "", ""])[:4]
                    name = name.lstrip("/")
                    if name.startswith(EXEC_DENY_PREFIXES):
                        continue
                    label = svc if svc and svc != "<no value>" else name
                    for ip in ips.split():
                        out.setdefault(ip, label)
        except Exception as e:  # noqa: BLE001 -- keep the previous map
            log("net target map failed:", e)
            return self._net_map
        if out != self._net_map:
            log(f"netsensor targets: {dict(sorted(out.items()))}")
        self._net_map = out
        self._net_unmapped = set()   # addresses may belong to a target after this refresh
        return out

    def _collect_net(self) -> bool:
        """Read new netsensor flow records. A stream that already exists when sensing starts
        (and no restore point) is skipped to its end: history is not activity."""
        p = NET_STREAM
        if not p or not p.exists():
            return False
        size = p.stat().st_size
        if self.net_off is None:
            self.net_off = 0 if self.resume_after is not None else size
        if size < self.net_off:   # truncated / rotated
            self.net_off = 0
        if size == self.net_off:
            return True
        with open(p, "rb") as f:
            f.seek(self.net_off)
            data = f.read(NET_MAX_READ)
        cut = data.rfind(b"\n") + 1
        self.net_off += cut
        targets = self.net_targets()
        for line in data[:cut].splitlines():
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if self.resume_after is not None and float(rec.get("ts") or 0) <= self.resume_after:
                continue
            self._net_record(rec, targets, hashlib.sha1(line).hexdigest())
        return True

    def _net_record(self, rec: dict, targets: dict, key: str):
        self.net_stats["records"] += 1
        src, dst, dport = rec.get("src"), rec.get("dst"), rec.get("dport")
        source = targets.get(dst)
        if (not source and dst and dst not in self._net_unmapped
                and time.time() - self._net_map_at >= NET_REMAP_MIN):
            # A target joined another network after the map was built (e.g. the Attack Box's
            # lab network): its new address must not be dropped as "untargeted" until the
            # periodic refresh. Rebuild at most every NET_REMAP_MIN seconds.
            targets.update(self.net_targets(force=True))
            source = targets.get(dst)
            if not source:   # e.g. the egress proxy: not a target; don't re-inspect for it
                self._net_unmapped.add(dst)
        if not source or not src:
            self.net_stats["untargeted"] += 1   # not a target container (e.g. Antigent, attackbox)
            return
        if rec.get("type") == "http":
            self.learn_self(src, rec.get("path"))
        internal = self.is_internal(src)   # scenario.json "internal" (same rule as the logs)
        if internal and not NET_KEEP_INTERNAL:
            self.net_stats["internal"] += 1
            return
        t = float(rec.get("ts") or time.time())
        is_http = rec.get("type") == "http"
        status = rec.get("status")
        path = rec.get("path")
        logged = source in self.log_client_roles   # this role's access log already names clients
        if is_http:
            kind = "net-http"
            summary = (f"{rec.get('method', '?')} {path or '/'} -> {status or 'no response'} "
                       f"from {src} to {source}:{dport}"
                       + (f" (basic user {rec['user']})" if rec.get("user") else "")
                       + (f" ({rec['auth']} auth)" if rec.get("auth") else ""))
        else:
            kind = "net-conn"
            summary = f"{rec.get('proto', 'tcp')} connection from {src} to {source}:{dport}"
        extra = {"client": src, "via": "netsensor", "dport": dport}
        extra.update({k: rec[k] for k in ("method", "path", "proto") if rec.get(k)})
        if source not in ROLES:
            extra["observe_only"] = True   # not a scenario role: no actions possible there
        if internal:
            extra["internal"] = True
        if is_http and logged and NET_DUP == "skip":
            self.net_stats["dup"] += 1
            return
        baseline_attrs = ({"client": src, "method": rec.get("method"), "path": path}
                          if is_http else {"client": src, "dport": dport})
        if not internal and self.matches_baseline(source, kind, baseline_attrs):
            self.sources.add((source, src))
            self.net_stats["events"] += 1
            self._add(source, kind, summary, json.dumps(rec, ensure_ascii=False),
                      dedup_key=f"net|{key}", level="baseline",
                      baseline_reason="clean_calibration", **extra)
            return
        if not internal and not logged:
            if (source, src) not in self.sources:
                self.sources.add((source, src))
                self._add(source, "new-source", f"first request from {src} on {source}", summary,
                          dedup_key=f"src|{source}|{src}", ip=src, via="netsensor")
            self._activity(source, src, status, path or f"tcp/{dport}", t, count_request=True)
            if is_http:
                self._request_rules(source, src, rec.get("method"), path, t)
            if is_http and status == "401":
                self.fail.setdefault((source, src), []).append((time.time(), rec.get("user"), path))
        self.net_stats["events"] += 1
        self._add(source, kind, summary, json.dumps(rec, ensure_ascii=False), dedup_key=f"net|{key}", **extra)

    def _activity(self, source, ip, status, path, t, count_request=True):
        """Two independent sliding windows per (role, client): all requests and 4xx (not 401)."""
        is_err = bool(status) and status.startswith("4") and status != "401"
        for kind, store, n, counts in (("recon-burst", self.req, RECON_N, count_request),
                                       ("error-burst", self.err, ERROR_N, is_err)):
            if not counts:
                continue
            hits = store.setdefault((source, ip), [])
            hits.append((t, path))
            hits[:] = [h for h in hits if t - h[0] <= RECON_WINDOW]
            if len(hits) < n:
                continue
            paths = []
            for h in hits:
                if h[1] and h[1] not in paths:
                    paths.append(h[1])
            what = "4xx responses" if kind == "error-burst" else "requests"
            self._add(source, kind,
                      f"{len(hits)} {what} from {ip} on {source} within {int(hits[-1][0] - hits[0][0]) + 1}s"
                      + (f"; paths: {', '.join(p[:60] for p in paths[:5])}" if paths else ""),
                      json.dumps({"ip": ip, "count": len(hits), "paths": paths[:20]}),
                      dedup_key=f"{kind}|{source}|{ip}|{hits[0][0]:.3f}", ip=ip, paths=paths[:20])
            hits.clear()   # next burst needs a fresh window

    def _auth_line(self, source, line) -> bool:
        for r in SC["_auth_dup"]:
            m = r.search(line)
            if m:
                self.last_user[source] = m.groupdict().get("user") or ""
                return True
        for r in SC["_auth_fail"]:
            m = r.search(line)
            if m:
                g = m.groupdict()
                if g.get("ip"):
                    self.sources.add((source, g["ip"].strip("[]")))
                user = g.get("user") or self.last_user.pop(source, None)
                key = g.get("ip") or user or "unknown"
                self.fail.setdefault((source, key), []).append((time.time(), user, g.get("path")))
                return True
        return False

    def _flush_auth(self, force: bool = False, source: str | None = None):
        now = time.time()
        only = source
        for (source, key), hits in list(self.fail.items()):
            if only is not None and source != only:
                continue
            hits = [h for h in hits if now - h[0] <= AUTH_WINDOW * 2]
            if not hits:
                del self.fail[(source, key)]
                continue
            span = now - hits[0][0]
            if force or len(hits) >= AUTH_BURST_N or span > AUTH_WINDOW:
                users = sorted({h[1] for h in hits if h[1]})
                paths = sorted({h[2] for h in hits if h[2]})
                kind = "auth-burst" if len(hits) >= AUTH_BURST_N else "auth-failure"
                who = ("(source not logged)" if key == "unknown"
                       else f"from {key}" if key not in users else f"for user {key}")
                summary = (f"{len(hits)} failed logins on {source} {who} within {int(span) + 1}s"
                           + (f"; users: {', '.join(users[:5])}" if users and key not in users else "")
                           + (f"; paths: {', '.join(p[:60] for p in paths[:3])}" if paths else ""))
                ip = key if re.fullmatch(r"[0-9a-fA-F.:\[\]]+", key or "") and key != "unknown" else None
                self._add(source, kind, summary,
                          json.dumps({"key": key, "count": len(hits), "users": users, "paths": paths[:10]}),
                          dedup_key=f"auth|{source}|{key}|{hits[0][0]}", **({"ip": ip.strip("[]")} if ip else {}))
                del self.fail[(source, key)]
            else:
                self.fail[(source, key)] = hits

    def _collect_diff(self, source, container, kind, ignore=()):
        """docker diff -> one event per changed path. Skipped: paths matching the sensor's
        `ignore` regexes (runtime churn), and "C <dir>" entries that only say a child changed.
        Changes right after an Antigent action on this role are level raw with cause=antigent,
        so Antigent's own decoys do not trigger its next turn."""
        try:
            code, out, err = self._docker(["diff", container])
            if code != 0:
                self._add(source, "error", f"docker diff {container} failed: {err.strip()[:200]}")
                return False
            entries = []
            for line in out.splitlines():
                line = line.strip()
                op, _, path = line.partition(" ")
                if not path or any(r.search(path) for r in ignore):
                    continue
                entries.append((op, path, line))
            paths = [p for _, p, _ in entries]
            own = self.self_active(source)
            for op, path, line in entries:
                if op == "C" and any(q.startswith(path.rstrip("/") + "/") for q in paths):
                    continue
                if own:
                    self._add(source, kind, line, level="raw", cause="antigent", internal=True)
                else:
                    self._add(source, kind, line)
            return True
        except Exception as e:  # noqa: BLE001
            self._add(source, "error", f"{source} diff unreadable: {e}")
            return False

    def since(self, since_index, limit):
        return [e for e in self.events if e["index"] > since_index][:limit]


# --------------------------------------------------------------------------- #
# Actions — executed HERE, inside the defense plane, never by the console
# --------------------------------------------------------------------------- #
_ADAPTER = None


_ADAPTER_MODULE = None


def adapter_module():
    """The scenario's adapter.py. Everything about its typed operations (names, roles, the
    form shown to the agent) comes from there; the gateway itself names none of them."""
    global _ADAPTER_MODULE
    if _ADAPTER_MODULE is None:
        path = SCENARIO_DIR / "adapter.py"
        spec = importlib.util.spec_from_file_location("antigent_bounded_scenario_adapter", path)
        if spec is None or spec.loader is None:
            raise RuntimeError("bounded scenario adapter cannot be loaded")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _ADAPTER_MODULE = module
    return _ADAPTER_MODULE


def typed_operations() -> dict:
    """operation name -> role, as declared by the scenario adapter ({} without one)."""
    try:
        return dict(getattr(adapter_module(), "OPERATIONS", {}) or {})
    except Exception:  # noqa: BLE001
        return {}


def typed_target_fields() -> dict:
    """operation name -> field names that identify its target, from the scenario adapter."""
    try:
        return dict(getattr(adapter_module(), "OPERATION_TARGETS", {}) or {})
    except Exception:  # noqa: BLE001
        return {}


def typed_action_forms() -> str:
    try:
        return str(getattr(adapter_module(), "ACTION_FORMS", "") or "")
    except Exception:  # noqa: BLE001
        return ""


def typed_adapter():
    global _ADAPTER
    if _ADAPTER is None:
        _ADAPTER = adapter_module().adapter_from_environment(DOCKER, role_container)
    return _ADAPTER


def run_action(action: dict, action_id: str | None = None) -> dict:
    """A note, or one reserved typed operation executed by the scenario adapter."""
    marker = str(action.get("marker", "") or "")
    base = {"role": action.get("role"), "marker": marker, "stdout": "", "stderr": "",
            "exit_code": None, "duration": 0.0}
    if "note" in action:
        if set(action) != {"note"}:
            return {**base, "label": "refused", "command": json.dumps(action)[:300],
                    "status": "refused", "stderr": "a note action cannot contain other fields"}
        return {**base, "label": "note", "command": f"# {action['note']}", "exit_code": 0, "status": "done"}
    if not action_id:
        return {**base, "label": "refused", "command": "typed operation without reservation",
                "status": "refused", "stderr": "a persistent reservation is required"}
    return typed_adapter().execute(action, action_id)


# The agent runs in a PERSISTENT OpenCode session (driver --continue): it remembers across turns
# what it planted, so the active-decoy / do-not-overwrite policy lives in AGENTS.md, not
# here. The gateway stays a thin executor. The only per-turn guard kept is "one submit per turn".
_SUBMITTED_TURN = None       # turn locked (a successful or exhausted submit); further submits refused
_ASSESSED_TURN = None        # turn whose assessment/decision were already recorded (dedupe retries)


def _as_obj(x):
    """Coerce a submit_turn field to a dict. Weak models often send the object as a JSON string
    (e.g. assessment: "{...}") -- json.loads it. Returns {} if it is not an object."""
    if isinstance(x, dict):
        return x
    if isinstance(x, str) and x.strip():
        try:
            v = json.loads(x)
            return v if isinstance(v, dict) else {}
        except ValueError:
            return {}
    return {}


def _as_list(x):
    """Coerce actions to a list of dicts; a JSON string or a single object is accepted too."""
    if isinstance(x, str) and x.strip():
        try:
            x = json.loads(x)
        except ValueError:
            return []
    if isinstance(x, dict):
        return [x]
    if isinstance(x, list):
        return [_as_obj(a) if not isinstance(a, dict) else a for a in x]
    return []


def do_submit_turn(params: dict) -> dict:
    global _SUBMITTED_TURN, _ASSESSED_TURN
    if DRIVER_TURN is not None and _SUBMITTED_TURN == DRIVER_TURN:
        return {"status": "already_submitted",
                "note": f"submit_turn was already accepted for turn T{DRIVER_TURN}. Stop now; do not submit again."}

    submitted_actions = _as_list(params.get("actions"))
    protocol_violations: list[str] = []

    def violation(reason: str, action_id: str | None = None) -> None:
        protocol_violations.append(reason)
        emit({"type": "protocol_violation", "protocol_id": PROTOCOL_ID,
              "turn": DRIVER_TURN, "action_id": action_id, "reason": reason})

    if DRIVER_REASON in READONLY_REASONS and submitted_actions:
        violation("reobservation_action")
        submitted_actions = []
    if len(submitted_actions) > 1:
        # Fail the whole submission before the first mutation: one observation, one action.
        violation("multiple_actions")
        submitted_actions = []

    assessment = _as_obj(params.get("assessment"))
    decision = _as_obj(params.get("decision"))
    if DRIVER_TURN is None or _ASSESSED_TURN != DRIVER_TURN:
        if assessment:
            emit_record("assessment", dict(assessment))
        if decision:
            emit_record("decision", dict(decision))
        _ASSESSED_TURN = DRIVER_TURN

    results = []
    executed_action_ids: list[str] = []
    delivered_action_ids: list[str] = []       # process exit 0; not target delivery
    target_delivered_action_ids: list[str] = []
    for a in submitted_actions:
        if not isinstance(a, dict):
            continue
        t0 = time.time()
        action_id = uuid.uuid4().hex[:10]
        reservation_id = None
        r = None
        is_note = "note" in a
        expected_role = typed_operations().get(a.get("operation"))
        if not is_note and (expected_role is None or a.get("role") != expected_role):
            violation("typed_operation_required", action_id)
            r = {"role": a.get("role"), "label": "refused", "command": "typed operation required",
                 "marker": "", "stdout": "", "stderr": "an allowed typed operation and its role are required",
                 "exit_code": None, "duration": 0.0, "status": "refused", "observations": [], "effect": None}
        if r is None and not is_note:
            reserved = gate().reserve(a, action_id, DRIVER_TURN)
            if not reserved.get("allowed"):
                reason = str(reserved.get("reason") or "reservation_refused")
                violation(f"reservation_{reason}", action_id)
                r = {"role": a.get("role"), "label": "refused", "command": "intervention reservation refused",
                     "marker": "", "stdout": "", "stderr": reason, "exit_code": None,
                     "duration": 0.0, "status": "refused", "observations": [], "effect": None}
            else:
                reservation = reserved["reservation"]
                reservation_id = reservation["reservation_id"]
                emit({"type": "action_start", "role": a.get("role"), "turn": DRIVER_TURN,
                      "action_id": action_id, "protocol_id": PROTOCOL_ID,
                      "reservation_id": reservation_id})
                try:
                    r = run_action(a, action_id)
                except Exception:
                    r = {"role": a.get("role"), "label": "exec", "command": "typed operation failed closed",
                         "marker": "", "stdout": "", "stderr": "typed operation raised; outcome is unverified",
                         "exit_code": 127, "duration": 0.0, "status": "done",
                         "observations": [], "effect": None}
                executed_action_ids.append(action_id)
        if r is None:
            r = run_action(a)          # a note
        r["action_id"] = action_id
        results.append(r)
        is_exec = r.get("label") == "exec"
        if is_exec and r.get("status") != "refused" and r.get("exit_code") == 0:
            delivered_action_ids.append(action_id)

        observation_ids = []
        native_status = []
        for wrapped in r.get("observations") or []:
            observation = wrapped.get("observation") if isinstance(wrapped, dict) else None
            if not isinstance(observation, dict):
                continue
            emit({"type": "action_observation", "action_id": action_id,
                  "protocol_id": PROTOCOL_ID, "observation": observation})
            if observation.get("evidence_id"):
                observation_ids.append(observation["evidence_id"])
            native_status.append({"type": wrapped.get("type"), "status": observation.get("status"),
                                  "evidence_id": observation.get("evidence_id")})
            if (observation.get("schema_version") == "delivery_observation_v1"
                    and observation.get("status") == "verified"):
                target_delivered_action_ids.append(action_id)
        r["native_status"] = native_status
        if action_id in executed_action_ids:
            try:
                gate().complete(action_id, exit_code=r.get("exit_code"), effect=r.get("effect"),
                              observation_ids=observation_ids)
            except Exception:
                violation("reservation_completion_failed", action_id)

        command = {
            "id": action_id, "side": "defender", "via": "gateway", "label": r["label"],
            "command": r["command"], "role": r.get("role"), "marker": r.get("marker") or None,
            "created": t0, "started": t0, "status": "rejected" if r["status"] == "refused" else "done",
            "exit_code": r["exit_code"], "duration": r["duration"], "turn": DRIVER_TURN, "operator": None,
            "stdout": r["stdout"], "stderr": r["stderr"],
            "protocol_id": PROTOCOL_ID, "reservation_id": reservation_id,
            "native_observation_ids": observation_ids,
        }
        emit({"type": "command", "command": command})

        marker_value = str(a.get("marker") or r.get("marker") or "")
        if marker_value and is_exec and r["status"] != "refused":
            if action_id in target_delivered_action_ids:
                emit_record("marker", {"value": marker_value, "role": r.get("role"),
                                       "action_id": action_id})
            else:
                emit_record("marker_failed", {"value": marker_value, "role": r.get("role"),
                                              "action_id": action_id, "exit_code": r.get("exit_code")})

    link_succeeded = False
    if DRIVER_REASON in READONLY_REASONS and REOBSERVE_ACTION_IDS:
        try:
            gate().link_reobservation(
                REOBSERVE_ACTION_IDS, DRIVER_TURN, final=DRIVER_REASON == "final_reobservation"
            )
            link_succeeded = True
        except Exception:
            violation("reobservation_link_failed")

    _SUBMITTED_TURN = DRIVER_TURN
    linked = REOBSERVE_ACTION_IDS if DRIVER_REASON == "reobservation" and link_succeeded else []
    final_linked = REOBSERVE_ACTION_IDS if DRIVER_REASON == "final_reobservation" and link_succeeded else []
    emit({"type": "turn_accepted", "turn": DRIVER_TURN, "reason": DRIVER_REASON or None,
          "attempts": 1, "intervened": bool(executed_action_ids),
          "protocol_id": PROTOCOL_ID,
          "protocol_violations": sorted(set(protocol_violations)),
          "executed_action_ids": executed_action_ids,
          "delivered_action_ids": delivered_action_ids,
          "target_delivered_action_ids": target_delivered_action_ids,
          "reobserved_action_ids": linked,
          "linked_reobserved_action_ids": linked,
          "final_reobserved_action_ids": final_linked})
    return {
        "ok": True,
        "recorded": str(DEFENSE_LOG),
        "protocol_id": PROTOCOL_ID,
        "protocol_violations": sorted(set(protocol_violations)),
        "retry": False,
        "actions": [{"id": r.get("action_id"), "label": r["label"], "role": r.get("role"),
                     "status": r["status"], "exit_code": r["exit_code"],
                     "stdout": r["stdout"][-800:], "stderr": r["stderr"][-800:],
                     "native_status": r.get("native_status") or []}
                    for r in results],
        "note": ("A mutating reservation is permanently recorded even on failure and locks this turn. "
                 "Native delivery/containment status is separate from exit_code; the driver schedules "
                 "reobservation."),
    }


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #
def _role_summary():
    return {r: {"description": s.get("description", ""),
                "sensors": [x.get("kind", x.get("type")) for x in s.get("sensors", [])],
                "exec": bool(s.get("exec", False))} for r, s in ROLES.items()}


def tools():
    return [
        {
            "name": "describe_scenario",
            "description": "Describe the environment you defend: its roles (the systems you can "
                           "observe and act on), their sensors, and scenario-specific context and "
                           "action examples. Call once at the start of your session.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "observe_events",
            "description": "Read defender-side telemetry for the scenario's roles (container logs, "
                           "filesystem changes) and return newly observed events. Read-only. Pass "
                           "since_index to get only events after one you have seen. This is the ONLY "
                           "input Antigent gets about the attack, never the attacker's terminal. "
                           "Returns EXTERNAL-client telemetry only; the range's own internal services "
                           "(e.g. CI re-indexing repos) are excluded as background noise. "
                           "Repeated login failures arrive aggregated as 'auth-burst' / 'auth-failure'.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "since_index": {"type": "integer", "default": 0},
                    "roles": {"type": "array", "items": {"type": "string", "enum": list(ROLES)},
                              "description": "Which roles to read. Default: all."},
                    "limit": {"type": "integer", "default": 100},
                    "include_baseline": {"type": "boolean", "default": False,
                                         "description": "Also return events that already existed when "
                                                        "sensing started (old logs, existing file changes)."},
                    "include_internal": {"type": "boolean", "default": False,
                                         "description": "Also return the range's own internal service "
                                                        "traffic (e.g. CI re-indexing repos). Off by default: "
                                                        "these are background noise, not the attacker."},
                },
            },
        },
        {
            "name": "submit_turn",
            "description": "Submit ONE defender turn: assessment, decision and at most one typed action. "
                           "The action is reserved before execution; the reservation is permanent and no "
                           "in-turn retry is allowed. Native delivery/containment is reported separately "
                           "from exit_code.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    # v0.15.3: compact schema -- every key is shown, evaluated or carried to the
                    # next turn; short values keep the turn fast (output tokens dominate latency).
                    "assessment": {"type": "object",
                                   "description": "① What the attacker is doing and will do next. Keep values short.",
                                   "properties": {"stage": {"type": "string",
                                                            "description": "kill-chain stage, 1-3 words"},
                                                  "intent": {"type": "string",
                                                             "description": "attacker objective, max 15 words"},
                                                  "evidence": {"type": "array", "items": {"type": "integer"},
                                                               "description": "event indexes only"},
                                                  "predicted_next": {
                                                      "type": "array", "maxItems": 2,
                                                      "description": "1-2 likely next steps, most likely first.",
                                                      "items": {"type": "object", "properties": {
                                                          "step": {"type": "string", "description": "max 10 words"},
                                                          "role": {"type": "string", "description": "role it will touch"},
                                                          "asset": {"type": "string",
                                                                    "description": "concrete path / repo / endpoint"},
                                                          "likelihood": {"type": "number"}}}},
                                                  "previous_prediction": {"type": "string",
                                                                          "enum": ["held", "partly", "missed", "none"],
                                                                          "description": "held = any predicted step happened"},
                                                  "confidence": {"type": "number"}}},
                    "decision": {"type": "object", "description": "② Strategy (a skill name, or no_intervention).",
                                 "properties": {"strategy": {"type": "string"},
                                                "preempts": {"type": "integer",
                                                             "description": "number of the predicted_next step these "
                                                                            "actions get ahead of; 0 = reactive"},
                                                "rationale": {"type": "string", "description": "one sentence, max 25 words"}}},
                    "actions": {
                        "type": "array",
                        "description": (
                            f"③ {PROTOCOL_ID}: at most ONE typed action, in a form the scenario adapter "
                            f"defines: {typed_action_forms()} No raw cmd. Empty for no_intervention."
                        ),
                        "items": {"type": "object"},
                    },
                },
                "required": ["assessment", "decision"],
            },
        },
    ]


def _public(ev: dict) -> dict:
    """What the agent sees of an event (internal dedup key dropped)."""
    return {k: v for k, v in ev.items() if k != "key"}


def read_sensor_stream() -> list[dict]:
    out = []
    try:
        with open(SENSOR_STREAM, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if ev.get("type") == "observed" and isinstance(ev.get("event"), dict):
                    out.append(ev["event"])
    except OSError:
        pass
    return out


def observe_from_stream(args: dict) -> dict:
    since = int(args.get("since_index", 0))
    limit = int(args.get("limit", 100))
    roles = set(args.get("roles") or ROLES)
    with_base = bool(args.get("include_baseline", False))
    # v0.16.4: by default the agent observes only EXTERNAL-client telemetry. Events the target's
    # own range services generate (internal: same Docker compose project -- a generic fact, not
    # scenario logic) are the range's background noise, not the attacker, and were being cited as
    # attacker evidence. Drop them unless the caller explicitly asks for them.
    with_internal = bool(args.get("include_internal", False))
    allev = read_sensor_stream()
    max_index = max((int(e.get("index", 0)) for e in allev), default=0)
    new = [e for e in allev if int(e.get("index", 0)) > since and e.get("source") in roles]
    base = [e for e in new if e.get("level") == "baseline"]
    if not with_base:
        new = [e for e in new if e.get("level") != "baseline"]
    internal = [e for e in new if e.get("internal")]
    if not with_internal:
        new = [e for e in new if not e.get("internal")]
    # Paginate in stream order. Reordering or advancing to scan_max_index would skip events
    # that did not fit in this page. The driver separately prioritises elevated triggers.
    limit = max(1, limit)
    truncated = len(new) > limit
    page = new[:limit]
    next_since = int(page[-1].get("index", since)) if page else since
    res = {"events": [_public(e) for e in page], "count": len(page),
           "max_index": next_since, "next_since_index": next_since,
           "scan_max_index": max_index, "truncated": truncated, "dropped": 0, "mode": "stream",
           "elevated": sum(1 for e in page if e.get("level") == "elevated"),
           "hint": "Pass next_since_index as since_index next time; repeat while truncated. "
                   "scan_max_index is the newest scanned index, not a safe cursor for a full page. "
                   "These are external-client events only; the range's own internal services are excluded."}
    if base and not with_base:
        res["baseline_skipped"] = len(base)
    if internal and not with_internal:
        res["internal_skipped"] = len(internal)
    if not allev and not SENSOR_STREAM.exists():
        res["warning"] = (f"sensor stream {SENSOR_STREAM} does not exist: is the sensor daemon "
                          "(gateway/sensor.py) running?")
    return res


def call_tool(name: str, args: dict) -> dict:
    if name == "describe_scenario":
        return {"scenario": SC.get("name"), "description": SC.get("description", ""),
                "roles": _role_summary(), "exec_roles": exec_roles(), "context": SC["_context"]}
    if name == "observe_events":
        if SENSOR_STREAM is None:
            raise RuntimeError("SENSOR_STREAM is not set: observation comes from the sensor daemon")
        return observe_from_stream(args)
    if name == "submit_turn":
        return do_submit_turn(args)
    raise ValueError(f"unknown tool: {name}")


# --------------------------------------------------------------------------- #
# JSON-RPC / MCP loop
# --------------------------------------------------------------------------- #
def reply(id_, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": id_}
    if error is not None:
        msg["error"] = error
    else:
        msg["result"] = result
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def handle(msg: dict):
    method = msg.get("method")
    id_ = msg.get("id")
    params = msg.get("params") or {}
    if method == "initialize":
        reply(id_, {"protocolVersion": params.get("protocolVersion", PROTOCOL_VERSION),
                    "capabilities": {"tools": {}}, "serverInfo": SERVER_INFO})
    elif method == "notifications/initialized":
        pass
    elif method == "ping":
        reply(id_, {})
    elif method == "tools/list":
        reply(id_, {"tools": tools()})
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        t_call = time.time()
        try:
            result = call_tool(name, args)
            text = json.dumps(result, ensure_ascii=False)
            reply(id_, {"content": [{"type": "text", "text": text}],
                        "isError": not result.get("ok", True)})
            # v0.16.7: per-call timing and payload size (what the agent was handed), for the
            # latency breakdown. Logging only -- no behaviour change.
            emit({"type": "tool_call", "tool": name, "turn": DRIVER_TURN, "started": t_call,
                  "secs": round(time.time() - t_call, 3), "out_bytes": len(text.encode("utf-8")),
                  "events": result.get("count") if name == "observe_events" else None})
        except Exception as e:  # noqa: BLE001
            log("tool error:", e)
            emit({"type": "tool_call", "tool": name, "turn": DRIVER_TURN, "started": t_call,
                  "secs": round(time.time() - t_call, 3), "error": str(e)[:200]})
            reply(id_, {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True})
    elif id_ is not None:
        reply(id_, error={"code": -32601, "message": f"method not found: {method}"})


# --------------------------------------------------------------------------- #
# Run manifest (v0.13.1): which policy / model / scenario produced this run.
# Written once per gateway start in the agent_start event, so exported logs can be
# compared across runs (policy A vs B, model X vs Y) without guessing.
# --------------------------------------------------------------------------- #
def _sha256_files(files: list[Path], base: Path) -> tuple[str, dict]:
    """Content hash over (relative path, bytes) of every file, order-independent."""
    h, per = hashlib.sha256(), {}
    for f in sorted(files, key=lambda x: x.relative_to(base).as_posix()):
        rel = f.relative_to(base).as_posix()
        data = f.read_bytes()
        per[rel] = hashlib.sha256(data).hexdigest()[:12]
        h.update(rel.encode() + b"\0" + data + b"\0")
    return h.hexdigest(), per


def _tree(folder: Path) -> list[Path]:
    return [f for f in folder.rglob("*") if f.is_file() and "__pycache__" not in f.parts] if folder.is_dir() else []


def run_manifest() -> dict:
    """Policy = AGENTS.md + .opencode/skills/ (the optimizable layer). Mechanism (gateway,
    opencode.lab.jsonc permissions) is hashed separately. No secrets: the API key is never read."""
    pol_files = [f for f in [REPO / "AGENTS.md"] if f.is_file()] + _tree(REPO / ".opencode" / "skills")
    pol_sha, pol_per = _sha256_files(pol_files, REPO)
    sc_sha, _ = _sha256_files(_tree(SCENARIO_DIR), SCENARIO_DIR)
    cfg_path = Path(os.environ.get("OPENCODE_CONFIG") or (REPO / "opencode.free.jsonc"))
    mech_files = [f for f in [Path(__file__).resolve(), cfg_path] if f.is_file()]
    mech_sha, _ = _sha256_files(mech_files, REPO)
    oc_model = None
    try:
        m = re.search(r'^\s*"model"\s*:\s*"([^"]+)"', cfg_path.read_text(encoding="utf-8"), re.M)
        oc_model = m.group(1) if m else None
    except OSError:
        pass
    base = os.environ.get("LLM_BASE_URL") or ""
    host = re.sub(r"^[a-z]+://", "", base).split("/")[0].split("@")[-1] or None
    return {
        "policy": {"sha256": pol_sha, "short": pol_sha[:12],
                   "label": os.environ.get("ANTIGENT_POLICY_LABEL") or None, "files": pol_per},
        "model": {"provider": ((os.environ.get("ANTIGENT_MODEL") or "").split("/")[0] or None),
                  "region": os.environ.get("AWS_REGION") or None,
                  "opencode_model": oc_model, "model_id": (os.environ.get("ANTIGENT_MODEL_LABEL") or os.environ.get("ANTIGENT_MODEL")
                               or os.environ.get("LLM_MODEL_ID") or None),
                  "config": cfg_path.name,
                  "endpoint_host": host},
        "scenario": {"name": SC.get("name"), "sha256": sc_sha, "short": sc_sha[:12]},
        "mechanism": {"gateway": SERVER_INFO["version"], "sha256": mech_sha, "short": mech_sha[:12],
                      "image": os.environ.get("ANTIGENT_IMAGE") or None},
    }


def main():
    roles = ", ".join(f"{r}={s['container']}" for r, s in ROLES.items())
    log(f"started. scenario={SC.get('name')} ({SCENARIO_DIR}) log={DEFENSE_LOG} roles: {roles}")
    try:
        manifest = run_manifest()
    except Exception as e:  # noqa: BLE001 -- never block the agent on bookkeeping
        log("run manifest failed:", e)
        manifest = {"error": str(e)}
    emit({"type": "agent_start", "scenario": SC.get("name"), "server": SERVER_INFO["version"], "run": manifest,
          "turn": DRIVER_TURN, "observe_mode": "stream"})
    log(f"run manifest: policy={manifest.get('policy', {}).get('short')} "
        f"model={manifest.get('model', {}).get('model_id')} scenario={manifest.get('scenario', {}).get('short')}")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            log("bad json:", e)
            continue
        try:
            handle(msg)
        except Exception as e:  # noqa: BLE001
            log("handler crash:", e)


if __name__ == "__main__":
    main()
