#!/usr/bin/env python3
"""Antigent event-driven driver (v0.15).

Starts ONE Antigent turn (`opencode run`) when the sensor stream has new ELEVATED events,
instead of relying on the model to keep looping by itself.

  sensor.jsonl --(elevated event)--> driver --(opencode run, one cycle)--> gateway tools

Rules (agreed 2026-11-14):
  * Trigger source is defender-side observation only (runs/defense/sensor.jsonl). The
    attacker stream is never read, not even for timing (O1 boundary).
  * Two tiers (v0.15). ELEVATED events (scenario.json "triggers": auth-burst, fs-change,
    new-source, recon-burst, error-burst, ...) start a turn quickly. Ordinary RAW activity
    (e.g. access-log lines during reconnaissance) also starts a turn, batched: at most one
    every DRIVER_ACTIVITY_INTERVAL s while activity continues, so Antigent can follow the
    attacker's progress and anticipate the next step. No activity -> no turns.
  * Debounce: wait DEBOUNCE s after the last elevated event (or at most MAX_WAIT s after
    the first one), so a burst becomes one turn.
  * One turn at a time. Events that arrive during a turn are handled by the next turn,
    after COOLDOWN s.
  * Each turn continues ONE OpenCode session (--continue) with a short prompt: the new event
    range and a digest of past actions; OpenCode keeps the session memory and compacts it.

Streams written (defense plane):
  runs/defense/driver.jsonl        trigger / turn_end events (trigger latency for eval)
  runs/defense/turns/turn-N.log    turn N's prompt and profile (model text and tool payloads omitted)
  runs/defense/driver.state.json   last handled event index and turn number (restart-safe)

Pause:  touch runs/defense/driver.pause   (remove to resume). Disable: ANTIGENT_DRIVER=0.

Config: SENSOR_STREAM, DEFENSE_LOG, ANTIGENT_MODEL (e.g. opencode/glm-5.3-flash-free; empty =
OpenCode's default / last chosen), DRIVER_DEBOUNCE (2), DRIVER_MAX_WAIT (15),
DRIVER_COOLDOWN (2), DRIVER_ACTIVITY_INTERVAL (20; 0 = elevated only), DRIVER_TURN_TIMEOUT (300),
DRIVER_POLL (1), OPENCODE_BIN (opencode).
Standard library only.
"""
import json
import math
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SENSOR = Path(os.environ.get("SENSOR_STREAM") or (REPO / "runs" / "defense" / "sensor.jsonl"))
DEFENSE = Path(os.environ.get("DEFENSE_LOG") or (REPO / "runs" / "defense" / "defense.jsonl"))
OUT_DIR = SENSOR.parent
DRIVER_LOG = OUT_DIR / "driver.jsonl"
STATE = OUT_DIR / "driver.state.json"
TURN_DIR = OUT_DIR / "turns"
PAUSE = OUT_DIR / "driver.pause"
FINALIZE_FLAG = OUT_DIR / "driver.finalize"
FINALIZED_FLAG = OUT_DIR / "driver.finalized.json"
WARMUP_FLAG = OUT_DIR / "driver.warmup"   # touch to force a fresh briefing (manual re-brief)

DEBOUNCE = float(os.environ.get("DRIVER_DEBOUNCE", "2"))
MAX_WAIT = float(os.environ.get("DRIVER_MAX_WAIT", "15"))
COOLDOWN = float(os.environ.get("DRIVER_COOLDOWN", "2"))
ACTIVITY = float(os.environ.get("DRIVER_ACTIVITY_INTERVAL", "20"))
TURN_TIMEOUT = float(os.environ.get("DRIVER_TURN_TIMEOUT", "300"))
# v0.17.1: the T0 briefing runs before any detection, so a hung model must not hold the driver for a full
# turn timeout. Default 120 s; on timeout the driver goes on watching and retries T0 at the next start.
WARMUP_TIMEOUT = float(os.environ.get("ANTIGENT_WARMUP_TIMEOUT", "120"))
WARMUP = os.environ.get("ANTIGENT_WARMUP", "1") != "0"   # T0 briefing at startup (default on)
POLL = float(os.environ.get("DRIVER_POLL", "1"))
MODEL = os.environ.get("ANTIGENT_MODEL", "").strip()
OPENCODE = os.environ.get("OPENCODE_BIN", "opencode")
VARIANT = os.environ.get("ANTIGENT_VARIANT", "").strip()       # reasoning effort; v2 form is -m model#variant
JSON_EVENTS = os.environ.get("ANTIGENT_OPENCODE_JSON", "1") != "0"   # profile each turn via --format json
INLINE_MAX = int(os.environ.get("DRIVER_INLINE_EVENTS", "40"))   # events handed in the prompt (0 = none)
TURN_RETRIES = int(os.environ.get("DRIVER_TURN_RETRIES", "1"))  # retries after a failed / unsubmitted turn
REOBSERVE_DELAY = float(os.environ.get("DRIVER_REOBSERVE_DELAY", "2"))
# End a turn as soon as the gateway has accepted its submission (the model's closing message
# after submit_turn changes nothing). Grace lets OpenCode persist the tool result first.
EARLY_EXIT = os.environ.get("DRIVER_EARLY_EXIT", "1") != "0"
EARLY_EXIT_GRACE = float(os.environ.get("DRIVER_EARLY_EXIT_GRACE", "1.0"))
REOBSERVE_TIMEOUT = float(os.environ.get("DRIVER_REOBSERVE_TIMEOUT", "120"))
# The only action protocol (typed operations, one per observation, serial reobservation).
PROTOCOL_ID = "context_managed_multi_turn_v1"
CONTEXT_SURFACE_LIMIT = int(os.environ.get("DRIVER_CONTEXT_SURFACES", "48"))
CONTEXT_CHAR_LIMIT = int(os.environ.get("DRIVER_CONTEXT_CHARS", "16000"))


def log(*a):
    print("[driver]", *a, file=sys.stderr, flush=True)


def emit(ev: dict):
    ev.setdefault("ts", time.time())
    ev.setdefault("plane", "defense")
    DRIVER_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(DRIVER_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(ev, ensure_ascii=False) + "\n")


# --------------------------------------------------------------------------- #
# Trigger decision (pure; unit-tested)
# --------------------------------------------------------------------------- #
class Pending:
    """Events not yet handed to a turn: elevated ones (fast tier) and raw ones (activity tier)."""

    def __init__(self):
        self.clear()

    def clear(self):
        self.first_ts = None   # wall-clock time the first pending elevated event was SEEN
        self.last_ts = None
        self.first_event_ts = None   # sensor timestamp of that event (for trigger latency)
        self.indexes: list[int] = []
        self.kinds: dict[str, int] = {}
        self.raw = 0
        self.raw_first_ts = None
        self.raw_first_event_ts = None
        self.events: list[dict] = []   # v0.16.7: compact bodies, handed to the agent in the prompt

    def add_raw(self, ev: dict, now: float):
        if self.raw_first_ts is None:
            self.raw_first_ts = now
            self.raw_first_event_ts = float(ev.get("ts") or now)
        self.raw += 1
        self._keep(ev)

    def _keep(self, ev: dict):
        if ev.get("internal") or ev.get("level") == "baseline":
            return
        self.events.append({k: ev.get(k) for k in ("index", "level", "kind", "source", "client", "summary")})

    def add(self, ev: dict, now: float):
        if self.first_ts is None:
            self.first_ts = now
            self.first_event_ts = float(ev.get("ts") or now)
        self.last_ts = now
        self.indexes.append(int(ev["index"]))
        self.kinds[ev.get("kind", "?")] = self.kinds.get(ev.get("kind", "?"), 0) + 1
        self._keep(ev)

    def __bool__(self):
        return bool(self.indexes)


def is_activity(ev: dict) -> bool:
    """v0.15.6: raw events that count toward an activity turn = requests from an EXTERNAL client
    (the line names a client address that is not one of the target's own services). Build logs,
    internal service traffic (e.g. Jenkins scanning Gitea) and Antigent's own changes do not."""
    return (ev.get("level") == "raw" and ev.get("kind") != "error"
            and bool(ev.get("client")) and not ev.get("internal"))


def should_fire(p: Pending, now: float, last_turn_end: float | None, paused: bool,
                debounce=DEBOUNCE, max_wait=MAX_WAIT, cooldown=COOLDOWN, activity=ACTIVITY) -> str | None:
    """'elevated' / 'activity' when a turn should start now, else None."""
    if paused or (not p and not p.raw):
        return None
    if last_turn_end is not None and now - last_turn_end < cooldown:
        return None
    if p:
        if now - p.last_ts >= debounce or now - p.first_ts >= max_wait:
            return "elevated"
        return None   # an elevated turn is imminent; do not pre-empt it with an activity turn
    if activity > 0 and p.raw:
        since = max(p.raw_first_ts, last_turn_end or 0)
        if now - since >= activity:
            return "activity"
    return None


def read_jsonl(path: "Path") -> list[dict]:
    """Read a JSONL file into a list of dicts; missing file / bad lines are skipped."""
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        pass
    return out


def build_warmup_prompt(roles: list[str]) -> str:
    """T0 briefing: hand the agent the scenario so the persistent session already understands the
    environment before the first attack. The agent only studies -- it does NOT observe or act."""
    return "\n".join([
        "[Antigent briefing — T0]",
        "You are Antigent, the defender. This is a CONTINUOUS session: from now on you will be "
        "re-prompted each time new attacker activity is detected, and you keep your memory across "
        "turns (OpenCode compacts it as it grows).",
        "RIGHT NOW is only a briefing. Do NOT call any tools. Do NOT observe, do NOT submit. Just "
        "read and understand the environment below, then reply in 2-3 sentences with: the roles you "
        "defend, the single most likely attack path, and which scenario-supported deception strategy "
        "and exact surface you would consider for one decoy. Wait for the first real turn before acting.",
        "--- Scenario ---",
        scenario_brief(),
        f"Exec roles (you may act on these later): {', '.join(roles)}.",
    ])


# --------------------------------------------------------------------------- #
# Deterministic, bounded context for context_managed_multi_turn_v1.
# Only allow-listed telemetry and native receipt fields are rendered. Raw event
# summaries, model text, commands, marker/decoy content and credentials are never
# copied into this digest.
_CONTEXT_TOKEN = re.compile(r"[A-Za-z0-9._~/%:@+\-]+")
_CONTEXT_NATIVE_STATUSES = {"verified", "not_delivered", "verified_ineffective", "unverified"}
_CONTEXT_COMPLETE_NATIVE_STATUSES = _CONTEXT_NATIVE_STATUSES - {"unverified"}


def _context_token(value, maximum: int = 240) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not 0 < len(value) <= maximum or not _CONTEXT_TOKEN.fullmatch(value):
        return None
    return value


def _context_path(value) -> str | None:
    """Keep a locator path, never its query/fragment or URL user information."""
    if not isinstance(value, str):
        return None
    value = value.strip().split("#", 1)[0].split("?", 1)[0]
    try:
        if "://" in value or value.startswith("//"):
            value = urlsplit(value).path
    except ValueError:
        return None
    return _context_token(value)


def _context_ts(value) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    return f"{value:.3f}"


def _compact_event_indexes(indexes: list[int]) -> str:
    """Render only observed indexes; never imply that gaps belong to the same surface."""
    ordered = sorted(set(indexes))
    if not ordered:
        return "#unavailable"
    ranges = []
    start = previous = ordered[0]
    for current in ordered[1:]:
        if current == previous + 1:
            previous = current
            continue
        ranges.append(f"#{start}" if start == previous else f"#{start}..#{previous}")
        start = previous = current
    ranges.append(f"#{start}" if start == previous else f"#{start}..#{previous}")
    return ",".join(ranges)


def _surface_history(upto: int) -> tuple[list[str], int]:
    surfaces: dict[tuple[str, str, str, str], dict] = {}
    for row in read_jsonl(SENSOR):
        if not isinstance(row, dict):
            continue
        event = row.get("event") or {}
        if not isinstance(event, dict):
            continue
        index = event.get("index")
        if (isinstance(index, bool) or not isinstance(index, int) or index <= 0 or index > upto
                or event.get("internal") or event.get("level") == "baseline"):
            continue
        # Ordinary telemetry is attacker-relevant only when it names an outside client.
        if event.get("level") != "elevated" and not event.get("client"):
            continue
        source = _context_token(event.get("source"), 80) or "unknown"
        kind = _context_token(event.get("kind"), 80) or "unknown"
        method = (_context_token(event.get("method"), 16) or "-").upper()
        path = _context_path(event.get("path")) or "-"
        key = (source, kind, method, path)
        item = surfaces.setdefault(key, {
            "first": index, "last": index, "first_ts": event.get("ts"),
            "last_ts": event.get("ts"), "count": 0, "observe_only": False, "indexes": [],
        })
        item["first"] = min(item["first"], index)
        item["last"] = max(item["last"], index)
        if index == item["first"]:
            item["first_ts"] = event.get("ts")
        if index == item["last"]:
            item["last_ts"] = event.get("ts")
        item["count"] += 1
        item["indexes"].append(index)
        item["observe_only"] = item["observe_only"] or bool(event.get("observe_only"))
    ordered = sorted(surfaces.items(), key=lambda item: item[1]["last"], reverse=True)
    lines = []
    for (source, kind, method, path), item in ordered:
        indexes = _compact_event_indexes(item["indexes"])
        first_ts, last_ts = _context_ts(item["first_ts"]), _context_ts(item["last_ts"])
        if first_ts and last_ts:
            timing = f" ts={first_ts}" if first_ts == last_ts else f" ts={first_ts}..{last_ts}"
        else:
            timing = ""
        observe_only = " observe_only" if item["observe_only"] else ""
        lines.append(f"{indexes}{timing} {source} {kind} {method} {path} "
                     f"count={item['count']}{observe_only}")
    return lines, len(lines)


def _receipt_history(defense_rows: list[dict]) -> tuple[list[str], bool]:
    """Return all sanitized reservation receipts and whether mutation context is complete."""
    complete = True
    native: dict[str, dict] = {}
    for row in defense_rows:
        if not isinstance(row, dict) or row.get("type") != "action_observation":
            continue
        action_id = row.get("action_id")
        observation = row.get("observation") or {}
        if isinstance(action_id, str) and isinstance(observation, dict):
            native[action_id] = observation
    state_path = OUT_DIR / "intervention_state.json"
    state = None
    if state_path.exists():
        try:
            candidate = json.loads(state_path.read_text(encoding="utf-8"))
            if isinstance(candidate, dict):
                state = candidate
            else:
                complete = False
        except (OSError, ValueError):
            complete = False
    if state is not None and (
            state.get("protocol_id") != PROTOCOL_ID
            or state.get("schema_version") != "intervention_state_v1"
            or state.get("max_interventions") is not None
            or not isinstance(state.get("reservations"), list)):
        complete = False
        state = None
    if state is None and any(isinstance(row, dict) and row.get("type") == "action_start"
                             for row in defense_rows):
        complete = False
    reservations = (state or {}).get("reservations") or []
    lines = []
    for reservation in reservations:
        if not isinstance(reservation, dict):
            complete = False
            continue
        raw_action_id = reservation.get("action_id")
        action_id = raw_action_id if (isinstance(raw_action_id, str)
                                      and re.fullmatch(r"[0-9a-f]{10}", raw_action_id)) else "unknown"
        if action_id == "unknown":
            complete = False
        turn = reservation.get("turn")
        turn_text = str(turn) if isinstance(turn, int) and not isinstance(turn, bool) and turn > 0 else "?"
        operation = reservation.get("operation")
        effect = reservation.get("effect") or {}
        target = effect.get("target") or {} if isinstance(effect, dict) else {}
        fields = []
        # Scenario-agnostic: render whatever exact target fields the adapter recorded,
        # in the adapter's own order.
        if isinstance(operation, str) and isinstance(target, dict) and target:
            for name, raw in target.items():
                value = _context_token(raw, 300) if isinstance(name, str) else None
                if value is None:
                    complete = False
                fields.append(f"{name}={value or 'unavailable'}")
        else:
            complete = False
            fields.append("target=unavailable")
        observation = (native.get(raw_action_id) or {}) if isinstance(raw_action_id, str) else {}
        status = observation.get("status")
        if status not in _CONTEXT_NATIVE_STATUSES:
            status = "missing_native_observation"
        if status not in _CONTEXT_COMPLETE_NATIVE_STATUSES:
            complete = False
        evidence = observation.get("evidence_id")
        observation_ids = reservation.get("observation_ids")
        if not isinstance(observation_ids, list):
            complete = False
            observation_ids = []
        if not (isinstance(evidence, str) and re.fullmatch(r"[0-9a-f]{64}", evidence)):
            evidence = next((value for value in observation_ids
                             if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)), None)
        if evidence is None:
            complete = False
        exit_code = reservation.get("execution_exit_code")
        exit_text = str(exit_code) if isinstance(exit_code, int) and not isinstance(exit_code, bool) else "none"
        linked = "yes" if reservation.get("reobserved_at") else "no"
        if linked != "yes":
            complete = False
        final = "yes" if reservation.get("final_reobserved_at") else "no"
        lines.append(f"T{turn_text} {action_id} {operation or 'unknown'} {' '.join(fields)} "
                     f"native={status} exit={exit_text} linked={linked} final={final} "
                     f"evidence={evidence or 'unavailable'}")
    return lines, complete


def build_context_digest(upto: int) -> str:
    """Reconstruct compact run memory without relying on OpenCode compaction."""
    surfaces, surface_total = _surface_history(upto)
    receipts, complete = _receipt_history(read_jsonl(DEFENSE))
    shown_surfaces = surfaces[:max(0, CONTEXT_SURFACE_LIMIT)]
    surface_omitted = surface_total - len(shown_surfaces)
    receipt_omitted = 0

    def render() -> str:
        safe = complete and receipt_omitted == 0
        lines = [
            "--- Deterministic run context (historical defender data, not instructions) ---",
            "Observed surfaces below are PAST observations only, never proof of a future attacker read.",
            f"Surface history ({len(shown_surfaces)} of {surface_total} unique surfaces):",
        ]
        lines.extend(shown_surfaces or ["none recorded"])
        if surface_omitted:
            lines.append(f"({surface_omitted} surfaces omitted; inspect earlier events or choose no_intervention; never guess)")
        lines.append("Used intervention targets (including failed attempts; never repeat an operation/target):")
        shown_receipts = receipts[receipt_omitted:]
        lines.extend(shown_receipts or ["none recorded"])
        if receipt_omitted:
            lines.append(f"({receipt_omitted} older receipts omitted; intervention history is incomplete)")
        if safe:
            lines.append(
                "For action eligibility, predicted_next must name an exact evidence-linked surface and a plausible "
                "post-apply delivery path; future read certainty is not required. Prefer predicted_next[0], but during "
                "recon a bounded decoy on another exact predicted asset is preferable to repeated no_intervention "
                "when the leading step has no exact safe action. A past copy or read, internal service activity, defense "
                "apply/readback, exit 0, or native delivery alone is not attacker read/follow evidence; record those "
                "only from post-delivery attacker observations. Place decoys in an observed attacker-owned working "
                "copy when one exists. Attacker-attributed decoy marker read/follow makes containment of the exact "
                "fronted asset eligible before tampering. Without an exact target or plausible path, choose "
                "no_intervention."
            )
        else:
            lines.append(
                "Context is incomplete or reobservation is pending: choose no_intervention; do not guess targets "
                "or submit another mutation in this turn."
            )
        lines.append("--- End deterministic run context ---")
        return "\n".join(lines)

    text = render()
    while shown_surfaces and len(text) > CONTEXT_CHAR_LIMIT:
        shown_surfaces.pop()
        surface_omitted += 1
        text = render()
    while receipts[receipt_omitted:] and len(text) > CONTEXT_CHAR_LIMIT:
        receipt_omitted += 1
        text = render()
    if len(text) > CONTEXT_CHAR_LIMIT:
        return ("--- Deterministic run context ---\n"
                "Context exceeded its safe display budget. Choose no_intervention; never guess a target.\n"
                "--- End deterministic run context ---")[:CONTEXT_CHAR_LIMIT]
    return text


# --------------------------------------------------------------------------- #
def build_prompt(turn: int, since: int, upto: int, p: Pending, roles: list[str],
                 reason: str = "elevated", first: bool = True, full_cycle: bool | None = None) -> str:
    """The message handed to `opencode run`. The OpenCode SESSION is persistent (--continue), so
    on continued turns the agent already holds the scenario, its past assessments/predictions and
    the decoys it planted -- the prompt is then just the new events + the one-cycle instruction.
    On the opening turn we give the scenario and the standing instructions once."""
    kinds = ", ".join(f"{k} x{n}" for k, n in sorted(p.kinds.items()))
    what = (f"{len(p.indexes)} elevated: {kinds}" + (f"; {p.raw} raw" if p.raw else "")) if p.indexes \
        else f"{p.raw} raw events, no elevated ones (ongoing activity, e.g. reconnaissance)"
    head = [
        f"[Antigent driver turn T{turn}]",
        f"New defender-side events since your last turn: indexes {since + 1}..{upto} ({what}).",
    ]
    listed = inline_events(p)
    step1 = (f"1. The new events are listed below (already filtered: outside clients only, old baseline "
             f"lines removed). Work from them directly. Call antigent_observe_events (since_index={since}) "
             f"ONLY if you need something that is not listed. Do NOT call describe_scenario."
             if listed else
             f"1. antigent_observe_events with since_index={since} (do NOT call describe_scenario).")
    submit_rule = (
        "3. antigent_submit_turn EXACTLY ONCE, then stop. There is NO in-turn retry after a mutating "
        "attempt, even on failure. Submit at most one typed operation; raw cmd is refused. A reservation "
        "is permanent even on failure. There is no fixed numeric intervention limit, but every new attempt "
        "needs new evidence, an unused exact target, and completed reobservation of the previous attempt. "
    )
    cycle = [
        "Do exactly ONE cycle, then stop and wait for the next turn:",
        step1,
        "2. Assess the new evidence together with what you already know from earlier turns: the "
        "attacker's intent, what they will do NEXT (predicted_next with role/asset), and whether "
        "your last prediction held.",
        submit_rule +
        "Use one assessment, one decision, and the actions in a single call. Get ahead of the predicted next "
        "step (decision.preempts is 1-based: predicted_next[0] = 1; 0 = reactive only). Select exactly one "
        "strategy Skill that the scenario explicitly marks available; "
        "artifact-path-decoy (factual) and in-environment-instruction (bounded instruction) are distinct, while "
        "deception-honeytoken is only their common rule set. Never infer an unadvertised adapter capability. You "
        "already planted the decoys listed in your own history -- never overwrite or replace one, and keep at most "
        "three active decoys per role; place each decoy in the observed attacker-owned working copy when one exists, "
        "at its top level or in a secrets-named directory (e.g. .secret/) under an ordinary file name. "
        "If an unread active decoy already covers the predicted step (same asset while the attacker is still reading "
        "it), choose no_intervention and watch for its use. Attacker-attributed decoy marker read/follow is confirmed "
        "intent and makes containment of the exact fronted asset eligible before tampering. A changed technique is not "
        "covered by an earlier decoy. Tampering in evidence remains a containment backstop for an exact observed target; "
        "being noticed is not by itself a reason to decline. Keep decoy content to at most 8 lines and 400 characters. "
        "An exact, evidence-linked, bounded decoy attempt is useful even if never read; do not require guaranteed future "
        "read. Choose no_intervention when no exact target or plausible delivery path exists.",
        "Do not wait, do not observe again after an accepted submission, do not loop; the turn ends when the "
        "submission is accepted. The driver records the reobservation of every mutating attempt itself; the "
        "next turn shows it in the history and receives the events that followed.",
        "YOU MUST call antigent_submit_turn before finishing. Ending the turn without exactly one "
        "submit_turn call is a failure. Even if you decide not to act, still submit: set "
        "decision.strategy=\"no_intervention\" and actions=[]. Never stop after only observing.",
        f"Exec roles: {', '.join(roles)}. Keep the JSON short (see the submit_turn schema limits).",
    ]
    tail = (["--- New events ---"] + listed) if listed else []
    context = [build_context_digest(upto)]
    if full_cycle is None:
        full_cycle = first
    if not first and full_cycle:
        return "\n".join(head + context + cycle + tail)
    if not first:
        # The full cycle was given on an earlier turn and AGENTS.md carries every rule in the
        # system prompt; repeating ~3k characters each turn only grew the session (and with it
        # the model's time to first token). Later turns get a short reminder instead.
        reminder = [
            "Do exactly ONE cycle as in AGENTS.md, then stop: " + (
                f"work from the events listed below (call antigent_observe_events with since_index={since} "
                "only if something you need is not listed); "
                if listed else f"call antigent_observe_events with since_index={since}; ")
            + "assess (intent, predicted_next, previous_prediction); then call antigent_submit_turn EXACTLY "
            "ONCE with at most one typed action in the exact tool-schema form (decision.strategy="
            "\"no_intervention\" and actions=[] when you do not act). No in-turn retry. "
            f"Exec roles: {', '.join(roles)}.",
        ]
        return "\n".join(head + context + reminder + tail)
    # opening turn: scenario + standing note (the session carries these forward)
    return "\n".join(head + [
        "This is a CONTINUOUS session: you will be re-prompted each time new events arrive. "
        "Remember, across turns, your running assessment, your predictions and every decoy you plant.",
        "--- Scenario ---",
        scenario_brief(),
    ] + context + ["--- Your task each turn ---"] + cycle + tail)


def build_reobservation_prompt(turn: int, since: int, upto: int, roles: list[str]) -> str:
    """A bounded, non-intervening turn required after every successful exec action."""
    context = [build_context_digest(upto)]
    return "\n".join([
        f"[Antigent driver turn T{turn} — REOBSERVATION]",
        "A previous turn made a mutating attempt. Complete exactly one readback/reobservation cycle now.",
    ] + context + [
        f"1. Call antigent_observe_events with since_index={since}. Events through index {upto} may be available; "
        "an empty result is valid evidence that no new attacker reaction was observed.",
        "2. Assess whether the previous prediction held and whether the intervention was followed. Do not invent "
        "delivery, read, follow, or decision-change evidence when none is visible.",
        "3. Call antigent_submit_turn exactly once with decision.strategy=\"no_intervention\" and actions=[]. "
        "This turn is read-only: no new intervention, marker, note action, or containment is allowed. Then stop.",
        f"Exec roles are suspended for this turn: {', '.join(roles)}.",
    ])


def inline_events(p: "Pending") -> list[str]:
    """v0.16.7: the driver already read these events, so hand them to the agent in the prompt
    instead of making it spend an LLM round trip on observe_events. All elevated events are kept;
    raw ones are the most recent, up to INLINE_MAX lines in total. Generic: no scenario logic."""
    if INLINE_MAX <= 0 or not p.events:
        return []
    elev = [e for e in p.events if e.get("level") == "elevated"]
    raw = [e for e in p.events if e.get("level") != "elevated"]
    room = max(0, INLINE_MAX - len(elev))
    keep = sorted(elev[-INLINE_MAX:] + (raw[-room:] if room else []), key=lambda e: int(e.get("index") or 0))
    out = []
    dropped = len(p.events) - len(keep)
    if dropped > 0:
        out.append(f"({dropped} older raw events not shown; call antigent_observe_events if you need them)")
    for e in keep:
        who = f" from {e['client']}" if e.get("client") else ""
        summ = " ".join(str(e.get("summary") or "").split())[:160]
        out.append(f"#{e.get('index')} {e.get('level')} {e.get('kind')} on {e.get('source')}{who}: {summ}")
    return out


# --------------------------------------------------------------------------- #
# Main loop
# --------------------------------------------------------------------------- #
def load_state() -> dict:
    try:
        return json.loads(STATE.read_text())
    except (OSError, ValueError):
        return {}


# True once the session has received the full per-turn cycle instructions; later turns then
# get only a short reminder (persisted, so a driver restart does not repeat or skip it).
_CYCLE_GIVEN = False


def save_state(st: dict):
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps({**st, "cycle_given": _CYCLE_GIVEN}))
    os.replace(tmp, STATE)


_BRIEF = None


def scenario_brief() -> str:
    """Compact scenario knowledge embedded in EVERY driver turn (each turn is a fresh, stateless
    `opencode run`): role names + one-line descriptions, exec roles, and the scenario context.md.
    This replaces the per-turn antigent_describe_scenario round-trip (v0.15.7)."""
    global _BRIEF
    if _BRIEF is not None:
        return _BRIEF
    scn = Path(os.environ.get("ANTIGENT_SCENARIO") or (REPO / "scenarios" / "cicd-goat"))
    lines = []
    try:
        sc = json.loads((scn / "scenario.json").read_text(encoding="utf-8"))
        lines.append(f"Scenario: {sc.get('name', scn.name)} -- {sc.get('description', '')}".rstrip())
        lines.append("Roles (target services you observe; actions run inside the exec ones):")
        for r, spec in sc.get("roles", {}).items():
            tag = " [exec]" if spec.get("exec") else " [observe-only]"
            lines.append(f"  - {r}{tag}: {spec.get('description', '')}".rstrip())
    except (OSError, ValueError):
        pass
    try:
        ctx = (scn / "context.md").read_text(encoding="utf-8").strip()
        if ctx:
            lines.append("Scenario context:\n" + ctx)
    except OSError:
        pass
    _BRIEF = "\n".join(lines)
    return _BRIEF


def exec_roles() -> list[str]:
    scn = Path(os.environ.get("ANTIGENT_SCENARIO") or (REPO / "scenarios" / "cicd-goat"))
    try:
        sc = json.loads((scn / "scenario.json").read_text(encoding="utf-8"))
        return [r for r, s in sc.get("roles", {}).items() if s.get("exec")]
    except (OSError, ValueError):
        return []


def parse_opencode_json(out: str) -> tuple[dict, str]:
    """v0.16.7: summarise `opencode run --format json` (one JSON event per line) into a per-turn
    profile -- how many LLM steps, how long each took, which tools ran and how long, and tokens --
    plus a readable transcript for turns/turn-N.log. Tolerant of unknown event shapes."""
    steps, tools, texts, errors = [], [], [], []
    tok = {"input": 0, "output": 0, "reasoning": 0, "cache_read": 0}
    open_step = None
    first_ts = last_ts = None
    for line in (out or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        typ, ts = ev.get("type"), ev.get("timestamp")
        if isinstance(ts, (int, float)):
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)
        part = ev.get("part") or {}
        if typ == "step_start":
            open_step = ts
        elif typ == "step_finish":
            t = part.get("tokens") or {}
            for k in ("input", "output", "reasoning"):
                tok[k] += int(t.get(k) or 0)
            tok["cache_read"] += int(((t.get("cache") or {}).get("read")) or 0)
            if open_step is not None and ts is not None:
                steps.append(round((ts - open_step) / 1000, 2))
            open_step = None
        elif typ == "tool_use":
            st = part.get("state") or {}
            tm = st.get("time") or {}
            secs = round((tm["end"] - tm["start"]) / 1000, 2) if tm.get("start") and tm.get("end") else None
            tools.append({"tool": part.get("tool"), "status": st.get("status"), "secs": secs})
            texts.append(f"[tool] {part.get('tool')} ({st.get('status')}, {secs}s) "
                         f"input={json.dumps(st.get('input'), ensure_ascii=False)[:400]}")
        elif typ in ("text", "reasoning"):
            if part.get("text"):
                texts.append(("[thinking] " if typ == "reasoning" else "") + part["text"])
        elif typ == "error":
            errors.append(json.dumps(ev.get("error"), ensure_ascii=False)[:300])
    prof = {"steps": len(steps), "step_secs": steps, "llm_secs": round(sum(steps), 2),
            "tools": tools, "tokens": tok}
    if errors:
        prof["errors"] = errors
    if first_ts is not None:
        prof["_first_ts"], prof["_last_ts"] = first_ts / 1000, last_ts / 1000
    return prof, "\n".join(texts)


def split_turn_time(prof: dict, t0: float, t_end: float) -> None:
    """Split the wall time of one `opencode run` into startup (process start -> first JSON
    event), the event span, and teardown (last event -> process exit), so the fixed per-turn
    overhead outside the LLM steps can be located."""
    first, last = prof.pop("_first_ts", None), prof.pop("_last_ts", None)
    if first is None or last is None:
        return
    prof["startup_secs"] = round(max(first - t0, 0.0), 2)
    prof["teardown_secs"] = round(max(t_end - last, 0.0), 2)


def _accepted_since(offset: int, turn: int) -> bool:
    try:
        with open(DEFENSE, encoding="utf-8") as f:
            f.seek(offset)
            for line in f:
                if '"turn_accepted"' not in line:
                    continue
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if ev.get("type") == "turn_accepted" and ev.get("turn") == turn:
                    return True
    except OSError:
        pass
    return False


def run_opencode(argv: list[str], env: dict, timeout: float, turn: int,
                 defense_offset: int) -> tuple[int, str, str, bool]:
    """Run one `opencode run`; stop it EARLY_EXIT_GRACE s after the gateway accepted this
    turn's submission. Returns (exit code, stdout, stderr, stopped early)."""
    import tempfile
    with tempfile.TemporaryFile("w+") as fo, tempfile.TemporaryFile("w+") as fe:
        try:
            proc = subprocess.Popen(argv, cwd=str(REPO), env=env, stdout=fo, stderr=fe, text=True)
        except FileNotFoundError as e:
            return 127, "", str(e), False
        deadline = time.monotonic() + timeout
        accepted_at = None
        code, early = None, False
        while code is None:
            code = proc.poll()
            if code is not None:
                break
            now = time.monotonic()
            if now >= deadline:
                proc.kill()
                proc.wait()
                code = 124
                fe.write(f"\n[driver] turn timed out after {timeout}s")
                break
            if EARLY_EXIT and accepted_at is None and _accepted_since(defense_offset, turn):
                accepted_at = now
            if accepted_at is not None and now - accepted_at >= EARLY_EXIT_GRACE:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                code, early = 0, True
                break
            time.sleep(0.2)
        fo.seek(0)
        fe.seek(0)
        return code, fo.read(), fe.read(), early


def run_turn(turn: int, since: int, upto: int, p: Pending, reason: str = "elevated",
             cont: bool = False, prompt: str | None = None, timeout: float | None = None) -> dict:
    # Persistent session: the first turn starts it; every later turn continues it with --continue,
    # so the agent keeps its memory and OpenCode compacts the context itself. The gateway stays
    # stateless -- the agent, not the gateway, remembers what it planted.
    global _CYCLE_GIVEN
    built_cycle = prompt is None and not _CYCLE_GIVEN
    if prompt is None:
        prompt = build_prompt(turn, since, upto, p, exec_roles(), reason, first=not cont,
                              full_cycle=not _CYCLE_GIVEN)
    # OpenCode 2 has no --variant flag; the variant rides on the model ref (provider/model#variant).
    model_arg = f"{MODEL}#{VARIANT}" if (MODEL and VARIANT) else (MODEL or "")
    if VARIANT and not MODEL:
        log("ANTIGENT_VARIANT set without ANTIGENT_MODEL -- ignored (v2 needs model#variant)")
    argv = ([OPENCODE, "run"] + (["--continue"] if cont else []) + (["-m", model_arg] if model_arg else [])
            + (["--format", "json"] if JSON_EVENTS else [])
            + [prompt])
    env = {**os.environ, "ANTIGENT_DRIVER_TURN": str(turn), "ANTIGENT_DRIVER_REASON": reason}
    reobserve_ids = getattr(p, "reobserved_action_ids", [])
    if reobserve_ids:
        env["ANTIGENT_REOBSERVE_ACTIONS"] = ",".join(reobserve_ids)
    TURN_DIR.mkdir(parents=True, exist_ok=True)
    try:
        defense_offset = DEFENSE.stat().st_size
    except OSError:
        defense_offset = 0
    t0 = time.time()
    emit({"type": "trigger", "turn": turn, "reason": reason, "since": since, "upto": upto,
          "elevated": p.indexes[:50], "kinds": p.kinds, "raw": p.raw,
          "first_elevated_ts": p.first_event_ts, "first_raw_ts": p.raw_first_event_ts,
          "model": MODEL or None, "prompt_chars": len(prompt), "inlined": len(p.events), "ts": t0})
    log(f"T{turn} ({reason}): events {since + 1}..{upto}, elevated {p.kinds}, raw {p.raw}")
    code, out, err, early = run_opencode(argv, env, timeout or TURN_TIMEOUT, turn, defense_offset)
    t_end = time.time()
    dur = round(t_end - t0, 2)
    raw_stderr_chars = len(err or "")
    prof, transcript = parse_opencode_json(out) if JSON_EVENTS else ({}, out)
    split_turn_time(prof, t0, t_end)
    if early:
        prof["early_exit"] = True   # stopped after acceptance; no closing model message
    # Never persist raw model text, tool input/output, decoy content or stderr.
    error_count = len(prof.get("errors") or [])
    prof.pop("errors", None)
    if error_count:
        prof["error_count"] = error_count
    transcript = "\n".join(
        f"[tool] {tool.get('tool')} ({tool.get('status')}, {tool.get('secs')}s)"
        for tool in prof.get("tools") or []
    ) or "[model text and tool payloads omitted]"
    err = f"[stderr omitted; {len(err or '')} chars]"
    if JSON_EVENTS:
        (TURN_DIR / f"turn-{turn}.jsonl").write_text(
            json.dumps({"type": "turn_profile", "profile": prof}) + "\n", encoding="utf-8")
    (TURN_DIR / f"turn-{turn}.log").write_text(
        f"# turn {turn}  exit {code}  {dur}s\n# PROFILE\n{json.dumps(prof, ensure_ascii=False)}\n"
        f"# PROMPT ({len(prompt)} chars)\n{prompt}\n\n# OUTPUT\n{transcript}\n\n# STDERR\n{err}\n",
        encoding="utf-8")
    accepted = None
    executed_seen = []
    try:
        with open(DEFENSE, encoding="utf-8") as f:
            f.seek(defense_offset)
            for line in f:
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if ev.get("type") == "turn_accepted" and ev.get("turn") == turn:
                    accepted = ev
                command = ev.get("command") or {}
                if (ev.get("type") == "command" and command.get("turn") == turn
                        and command.get("side") == "defender" and command.get("label") == "exec"
                        and command.get("status") != "rejected" and command.get("id")):
                    executed_seen.append(command["id"])
    except OSError:
        pass
    submitted = accepted is not None
    executed_ids = list(dict.fromkeys(
        (accepted or {}).get("executed_action_ids") or executed_seen
    ))
    intervened = bool((accepted or {}).get("intervened")) or bool(executed_ids)
    final_reobserved_ids = (accepted or {}).get("final_reobserved_action_ids") or []
    emit({"type": "turn_end", "turn": turn, "exit_code": code, "duration": dur,
          "submitted": submitted, "intervened": intervened,
          "protocol_id": PROTOCOL_ID or None, "executed_action_ids": executed_ids,
          "target_delivered_action_ids": (accepted or {}).get("target_delivered_action_ids") or [],
          "final_reobserved_action_ids": final_reobserved_ids,
          "profile": prof or None, "stderr_tail": None,
          "stderr_chars": raw_stderr_chars})
    log(f"T{turn}: exit {code} in {dur}s; submitted={submitted}; intervened={intervened}" +
        (f"; {prof.get('steps')} LLM steps, tools {[t.get('tool') for t in prof.get('tools', [])]}, "
         f"tokens {prof.get('tokens')}" if prof else ""))
    if built_cycle and code == 0 and submitted:
        _CYCLE_GIVEN = True       # the session now holds the full cycle instructions
    return {"exit_code": code, "duration": dur, "submitted": submitted, "intervened": intervened,
            "executed_action_ids": executed_ids,
            "target_delivered_action_ids": (accepted or {}).get("target_delivered_action_ids", []),
            "final_reobserved_action_ids": final_reobserved_ids,
            "delivered_action_ids": (accepted or {}).get("delivered_action_ids", [])}


def turn_succeeded(result: dict | None) -> bool:
    """A driver turn is complete only after a clean exit AND gateway acceptance."""
    return bool(result and result.get("exit_code") == 0 and result.get("submitted"))


def run_bounded_turn(turn: int, since: int, upto: int, p: Pending, reason: str = "elevated",
                     cont: bool = False, prompt: str | None = None,
                     timeout: float | None = None) -> dict:
    """Retry only missing submissions; never repeat an accepted intervention after a CLI error."""
    result = run_turn(turn, since, upto, p, reason, cont, prompt, timeout)
    for retry in range(1, TURN_RETRIES + 1):
        if result.get("submitted") or result.get("executed_action_ids"):
            break
        emit({"type": "turn_retry", "turn": turn, "retry": retry, "reason": reason,
              "previous_exit_code": result.get("exit_code")})
        result = run_turn(turn, since, upto, p, reason, cont, prompt, timeout)
    return result


def run_warmup(cont: bool) -> bool:
    """One briefing turn (T0). cont=False starts the session; cont=True re-briefs an existing one.
    Returns True only if the briefing turn exited 0, so the caller marks the session started
    only on success (a failed T0 -- e.g. no model, LLM error -- is retried on the next start)."""
    log("T0 briefing (" + ("re-brief, --continue" if cont else "new session") + f", timeout {WARMUP_TIMEOUT:.0f}s)")
    r = run_turn(0, 0, 0, Pending(), reason="briefing", cont=cont,
                 prompt=build_warmup_prompt(exec_roles()), timeout=WARMUP_TIMEOUT)
    ok = (r or {}).get("exit_code") == 0
    if not ok:
        log("T0 briefing did not succeed; will retry on next start (session not marked started)")
    return ok


def reobserve_deterministic(action_ids: list[str], turn: int, since: int, upto: int) -> None:
    """Post-apply reobservation without a model turn: after REOBSERVE_DELAY the driver links
    the attempt to the telemetry window that followed it (the gate then allows the next
    action). Whether that window shows the attacker reading or following the attempt is judged
    in the next decision turn, which receives these events and the linked receipt history."""
    if not action_ids:
        return
    from intervention_gate import InterventionGate
    InterventionGate(DEFENSE.parent / "intervention_state.json", defense_log=DEFENSE).link_reobservation(
        list(action_ids), turn)
    emit({"type": "reobservation", "turn": turn, "mode": "deterministic",
          "action_ids": list(action_ids), "since": since, "upto": upto})
    log(f"T{turn}: reobservation linked for {len(action_ids)} action(s) (events up to {upto})")


def executed_actions() -> list[str]:
    ids = []
    for row in read_jsonl(DEFENSE):
        if row.get("type") == "turn_accepted" and row.get("protocol_id") == PROTOCOL_ID:
            for action_id in row.get("executed_action_ids") or []:
                if action_id not in ids:
                    ids.append(action_id)
    return ids


def run_final_reobservation(turn: int, since: int, session_started: bool) -> dict:
    """One final read-only turn after the attacker stops, distinct from post-apply checks."""
    action_ids = executed_actions()
    if not action_ids:
        receipt = {"schema_version": "final_reobservation_v1", "turn": None,
                   "accepted": True, "final_reobserved_action_ids": [], "ts": time.time()}
        FINALIZED_FLAG.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
        return {"exit_code": 0, "submitted": True, "executed_action_ids": []}
    upto = max((int((row.get("event") or {}).get("index", 0))
                for row in read_jsonl(SENSOR)), default=0)
    prompt = build_reobservation_prompt(turn, since, upto, exec_roles()).replace(
        "[Antigent driver turn", "[Antigent FINAL driver turn"
    ).replace("A previous turn made a mutating attempt.",
              "The attacker has stopped. Perform the FINAL read-only reobservation for all mutating attempts.")
    pending = Pending()
    pending.reobserved_action_ids = action_ids
    result = run_bounded_turn(turn, since, upto, pending, "final_reobservation",
                              cont=session_started, prompt=prompt, timeout=REOBSERVE_TIMEOUT)
    receipt = {"schema_version": "final_reobservation_v1", "turn": turn,
               "accepted": turn_succeeded(result),
               "final_reobserved_action_ids": result.get("final_reobserved_action_ids") or [],
               "ts": time.time()}
    FINALIZED_FLAG.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main():
    if os.environ.get("ANTIGENT_DRIVER", "1") == "0":
        log("disabled (ANTIGENT_DRIVER=0)")
        return
    global _CYCLE_GIVEN
    st = load_state()
    turn = int(st.get("turn", 0))
    session_started = bool(st.get("session_started", turn > 0))
    _CYCLE_GIVEN = bool(st.get("cycle_given")) and session_started
    pos = 0
    max_index = 0
    # Start after what already exists, unless we are resuming a previous state.
    for line in read_jsonl(SENSOR):
        ev = line.get("event") or {}
        max_index = max(max_index, int(ev.get("index", 0)))
    try:
        pos = SENSOR.stat().st_size
    except OSError:
        pos = 0
    handled = int(st.get("handled", max_index))
    if handled > max_index:   # sensor stream was reset -> start over
        handled = max_index
    pending = Pending()
    last_end = None
    log(f"watching {SENSOR} from index {handled} (turn {turn}); model={MODEL or '(OpenCode default)'}; "
        f"debounce={DEBOUNCE}s max_wait={MAX_WAIT}s cooldown={COOLDOWN}s activity={ACTIVITY}s")
    save_state({"handled": handled, "turn": turn, "session_started": session_started})
    if WARMUP and not session_started:
        # T0: prime the session with the scenario before any attack. Mark the session started
        # ONLY if the briefing turn succeeded (exit 0); otherwise leave it so the next start retries.
        if run_warmup(cont=False):
            session_started = True
            save_state({"handled": handled, "turn": turn, "session_started": session_started})
    buf = b""
    while True:
        now = time.time()
        try:
            size = SENSOR.stat().st_size if SENSOR.exists() else 0
            if size < pos:   # truncated / replaced
                pos, buf = 0, b""
            if size > pos:
                with open(SENSOR, "rb") as f:
                    f.seek(pos)
                    buf += f.read()
                    pos = f.tell()
                *lines, buf = buf.split(b"\n")
                for line in lines:
                    try:
                        ev = json.loads(line).get("event") or {}
                    except ValueError:
                        continue
                    idx = int(ev.get("index", 0))
                    max_index = max(max_index, idx)
                    if idx > handled and ev.get("level") == "elevated":
                        pending.add(ev, now)
                    elif idx > handled and is_activity(ev):
                        pending.add_raw(ev, now)
        except OSError as e:
            log("read failed:", e)
        if WARMUP_FLAG.exists():
            try:
                WARMUP_FLAG.unlink()
            except OSError:
                pass
            if run_warmup(cont=session_started):
                session_started = True
            last_end = time.time()
            save_state({"handled": handled, "turn": turn, "session_started": session_started})
        if FINALIZE_FLAG.exists() and not FINALIZED_FLAG.exists():
            turn += 1
            final_result = run_final_reobservation(turn, handled, session_started)
            last_end = time.time()
            save_state({"handled": handled, "turn": turn, "session_started": session_started,
                        "finalized": turn_succeeded(final_result)})
            if not turn_succeeded(final_result):
                emit({"type": "driver_failed", "turn": turn, "reason": "final_reobservation",
                      "result": final_result})
                raise SystemExit(1)
        reason = should_fire(pending, now, last_end, PAUSE.exists())
        if reason:
            turn += 1
            upto = max_index
            result = run_bounded_turn(turn, handled, upto, pending, reason, cont=session_started)
            if not turn_succeeded(result):
                emit({"type": "driver_failed", "turn": turn, "reason": reason,
                      "unhandled_since": handled, "unhandled_upto": upto, "result": result})
                save_state({"handled": handled, "turn": turn, "session_started": session_started,
                            "failed": True})
                raise SystemExit(1)
            session_started = True
            handled = upto
            pending.clear()
            last_end = time.time()
            save_state({"handled": handled, "turn": turn, "session_started": session_started})
            if result.get("intervened"):
                # No new attacker event is required: every delivered action gets one bounded,
                # read-only reobservation before any subsequent intervention turn.
                time.sleep(REOBSERVE_DELAY)
                re_upto = max(max_index, max((int((line.get("event") or {}).get("index", 0))
                                              for line in read_jsonl(SENSOR)), default=0))
                try:
                    reobserve_deterministic(result.get("executed_action_ids", []), turn,
                                            handled, re_upto)
                except Exception as exc:  # noqa: BLE001 -- the gate refuses further actions
                    emit({"type": "driver_failed", "turn": turn, "reason": "reobservation",
                          "unhandled_since": handled, "unhandled_upto": re_upto,
                          "error": str(exc)[:300]})
                    save_state({"handled": handled, "turn": turn,
                                "session_started": session_started, "failed": True})
                    raise SystemExit(1)
                save_state({"handled": handled, "turn": turn, "session_started": session_started})
        time.sleep(POLL)


if __name__ == "__main__":
    main()
