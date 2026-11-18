#!/usr/bin/env python3
"""Antigent evaluation metrics.

Reads the plane-separated event log (v0.11) and reports:

  Attack progression   attacker command count, wall-clock duration, commands/min.
  Detection            time-to-first-detection (first assessment at/above a confidence
                       threshold, or the first auth-burst), number of interventions.
  Honeytoken access    for each decoy Antigent planted (marker), whether and when the
                       attacker used it (an attacker command referencing the value).
  Intervention impact  attacker command error rate before vs after the first
                       intervention (best-effort, from exit codes).

Usage:
  python eval/metrics.py runs                      # merge streams; latest console session if any, else all
  python eval/metrics.py runs --all                # everything in runs/
  python eval/metrics.py runs --session <id>       # one console session
  python eval/metrics.py runs --since <unix ts> [--until <unix ts>]   # headless harness window
  python eval/metrics.py old-session.jsonl         # v0.10 single-file session log (legacy)

Streams (see eval/streams.py): runs/defense/defense.jsonl (gateway),
runs/attacker/attacker.jsonl (attackbox hook), runs/console/*.jsonl (session markers).
The Console is NOT required: headless training runs are evaluated the same way. These are the metrics agreed on 2026-11-14:
attack speed (commands / time), access to Antigent-planted files, and the effect of
intervention on the attacker's subsequent commands.
"""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import streams  # noqa: E402


def load(path):
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except ValueError:
                    pass
    return events


def final_commands(events):
    """Last state of each command id (commands are re-emitted as they progress)."""
    cmds = {}
    for e in events:
        if e.get("type") == "command":
            c = e["command"]
            cmds[c["id"]] = c
    return list(cmds.values())


def rate(flags):
    flags = [f for f in flags if f is not None]
    return (sum(1 for f in flags if f) / len(flags)) if flags else None


def compute(events, conf_threshold=0.5):
    cmds = final_commands(events)
    recs = [e["record"] for e in events if e.get("type") == "record"]
    att = sorted((c for c in cmds if c["side"] == "attacker"), key=lambda c: c["created"])
    t0 = att[0]["created"] if att else None
    t_last = att[-1]["created"] if att else None
    duration = (t_last - t0) if t0 is not None else 0.0

    # Detection: first assessment >= threshold, else first auth-burst event is not in
    # this stream (it's on the gateway side) -> use first assessment with evidence.
    detect_ts = None
    for r in sorted(recs, key=lambda r: r["created"]):
        if r.get("kind") == "assessment":
            try:
                if float(r.get("confidence", 0)) >= conf_threshold:
                    detect_ts = r["created"]
                    break
            except (TypeError, ValueError):
                continue
    ttd = (detect_ts - t0) if (detect_ts is not None and t0 is not None) else None

    decisions = [r for r in recs if r.get("kind") == "decision"]
    interventions = [d for d in decisions if (d.get("strategy") or "") not in ("", "no_intervention")]
    dcmds = []
    for c in cmds:
        if c["side"] != "defender" or c.get("via") != "gateway":
            continue
        # Legacy records have no label: their notes are recognisable by the synthetic '# ' command.
        if c.get("label") == "note" or (not c.get("label") and str(c.get("command", "")).startswith("# ")):
            continue
        dcmds.append(c)
    successful_dcmds = [c for c in dcmds if c.get("status") != "rejected" and c.get("exit_code") == 0]
    first_iv_ts = min((c["created"] for c in successful_dcmds), default=None)
    accepted = [e for e in events if e.get("type") == "turn_accepted"]
    reobserved_ids = {a for e in accepted if e.get("reason") == "reobservation"
                      for a in e.get("reobserved_action_ids", [])}
    linked_reobserved_ids = {a for e in accepted if e.get("reason") == "reobservation"
                             for a in e.get("linked_reobserved_action_ids", [])}
    final_reobserved_ids = {a for e in accepted if e.get("reason") == "final_reobservation"
                           for a in e.get("final_reobserved_action_ids", [])}
    executed_ids = {a for e in accepted for a in e.get("executed_action_ids", [])}
    target_delivered_ids = {a for e in accepted for a in e.get("target_delivered_action_ids", [])}
    native_observations = [e.get("observation") or {} for e in events
                           if e.get("type") == "action_observation"]
    delivery_observations = [o for o in native_observations
                             if o.get("schema_version") == "delivery_observation_v1"]
    containment_observations = [o for o in native_observations
                                if o.get("schema_version") == "containment_observation_v1"]

    # Delivery, attacker read/output exposure, subsequent use, and reobservation are distinct.
    markers = [r for r in recs if r.get("kind") == "marker" and r.get("value")]
    honey = []
    for marker in markers:
        plant_ts = marker["created"]
        value = str(marker.get("value", ""))
        action_id = marker.get("action_id")
        read = [c for c in att if value and c["created"] >= plant_ts
                and value in (str(c.get("stdout", "")) + str(c.get("stderr", "")))]
        followed = [c for c in att if value and value in (c.get("command", ""))
                    and c["created"] >= plant_ts]
        used = read + [c for c in followed if c not in read]
        first = min((c["created"] for c in used), default=None)
        delivered = any(c.get("id") == action_id for c in successful_dcmds) if action_id else True
        honey.append({"value": value, "action_id": action_id, "planted_at": round(plant_ts, 1),
                      "delivered": delivered,
                      "target_delivered": bool(action_id and action_id in target_delivered_ids),
                      "read": bool(read), "followed": bool(followed),
                      "decision_changed": None,
                      "reobserved": bool(action_id and action_id in reobserved_ids),
                      "linked_reobserved": bool(action_id and action_id in linked_reobserved_ids),
                      "accessed": bool(used), "accesses": len(used),
                      "read_count": len(read), "follow_count": len(followed),
                      "latency_s": round(first - plant_ts, 1) if first is not None else None})

    # Intervention impact: attacker command error rate before vs after first intervention.
    def err(c):
        ec = c.get("exit_code")
        return None if ec is None else (ec != 0)
    before = after = None
    if first_iv_ts is not None:
        before = rate([err(c) for c in att if c["created"] < first_iv_ts])
        after = rate([err(c) for c in att if c["created"] >= first_iv_ts])

    # Defender-side metrics: need only the defense stream (work without any attacker stream).
    allobs = [e["event"] for e in events if e.get("type") == "observed" and isinstance(e.get("event"), dict)]
    # v0.14: baseline events (already there when sensing started) are not activity.
    observed = [o for o in allobs if o.get("level") != "baseline"]
    obs_ts = sorted(float(o.get("ts") or 0) for o in observed if o.get("kind") != "error")
    burst_ts = sorted(float(o.get("ts") or 0) for o in observed if o.get("kind") == "auth-burst")
    elevated = [o for o in observed if o.get("level") == "elevated"]
    elev_ts = sorted(float(o.get("ts") or 0) for o in elevated)
    defense = {
        "observed_events": len(observed),
        "elevated_events": len(elevated),
        "baseline_events": len(allobs) - len(observed),
        "turns": len(decisions),
        "actions": len(dcmds),
        "actions_ok": sum(1 for c in dcmds if c.get("exit_code") == 0),
        "actions_refused": sum(1 for c in dcmds if c.get("status") == "rejected"),
        "reobservations": sum(1 for e in accepted if e.get("reason") == "reobservation"),
        "executed_actions": len(executed_ids),
        "target_delivered_actions": len(target_delivered_ids),
        "linked_reobserved_actions": len(linked_reobserved_ids),
        "final_reobserved_actions": len(final_reobserved_ids),
        "protocol_violations": sum(1 for e in events if e.get("type") == "protocol_violation"),
        "native_delivery_verified": sum(1 for o in delivery_observations if o.get("status") == "verified"),
        "native_delivery_not_delivered": sum(1 for o in delivery_observations if o.get("status") == "not_delivered"),
        "native_delivery_unverified": sum(1 for o in delivery_observations if o.get("status") == "unverified"),
        "containment_verified": sum(1 for o in containment_observations if o.get("status") == "verified"),
        "containment_verified_ineffective": sum(
            1 for o in containment_observations if o.get("status") == "verified_ineffective"
        ),
        "containment_unverified": sum(1 for o in containment_observations if o.get("status") == "unverified"),
        "driver_failures": sum(1 for e in events if e.get("type") == "driver_failed"),
        "first_observed_to_detection_s": (round(detect_ts - obs_ts[0], 1)
                                          if (detect_ts is not None and obs_ts) else None),
        "first_auth_burst_to_detection_s": (round(detect_ts - burst_ts[0], 1)
                                            if (detect_ts is not None and burst_ts) else None),
        "first_elevated_to_detection_s": (round(detect_ts - elev_ts[0], 1)
                                          if (detect_ts is not None and elev_ts) else None),
    }

    # v0.14 driver: how fast an elevated event became an Antigent turn, and turn health.
    # T0 is a model briefing, not an observation/intervention turn.
    trig = [e for e in events if e.get("type") == "trigger" and e.get("turn") != 0]
    ends = {}
    for e in events:
        if e.get("type") == "turn_end" and e.get("turn") != 0:
            ends.setdefault(e.get("turn"), []).append(e)
    lat = [float(t["ts"]) - float(t["first_elevated_ts"]) for t in trig if t.get("first_elevated_ts")]
    final_ends = {turn: values[-1] for turn, values in ends.items()}
    durs = [float(final_ends[t["turn"]]["duration"]) for t in trig if t.get("turn") in final_ends]
    driver = {
        "turns_triggered": len(trig),
        "turns_elevated": sum(1 for t in trig if t.get("reason", "elevated") == "elevated"),
        "turns_activity": sum(1 for t in trig if t.get("reason") == "activity"),
        "turns_reobservation": sum(1 for t in trig if t.get("reason") == "reobservation"),
        "turns_failed": sum(1 for t in trig if t.get("turn") in final_ends
                            and (final_ends[t["turn"]].get("exit_code") != 0
                                 or final_ends[t["turn"]].get("submitted") is False)),
        "turns_unsubmitted": sum(1 for t in trig if t.get("turn") in final_ends
                                 and final_ends[t["turn"]].get("submitted") is False),
        "driver_failures": sum(1 for e in events if e.get("type") == "driver_failed"),
        "trigger_latency_mean_s": round(sum(lat) / len(lat), 1) if lat else None,
        "trigger_latency_max_s": round(max(lat), 1) if lat else None,
        "turn_duration_mean_s": round(sum(durs) / len(durs), 1) if durs else None,
    }

    # v0.15 anticipation: predictions made, interventions that name a pre-empted step, and a
    # HEURISTIC hit rate (needs the attacker stream): a prediction "hits" if an attacker command
    # within PRED_HORIZON s after it mentions the predicted asset (or its last path segment).
    PRED_HORIZON = 300.0
    assess = [r for r in recs if r.get("kind") == "assessment"]
    with_pred = [r for r in assess if isinstance(r.get("predicted_next"), list) and r["predicted_next"]]
    preemptive = [d for d in interventions if d.get("preempts")]
    checked = hits = 0
    if att:
        for r in with_pred:
            assets = []
            for x in r["predicted_next"][:3]:
                a = str((x or {}).get("asset") or "").strip() if isinstance(x, dict) else ""
                if len(a) >= 4:
                    assets.append(a)
                    seg = a.rstrip("/").rsplit("/", 1)[-1]
                    if len(seg) >= 4 and seg != a:
                        assets.append(seg)
            if not assets:
                continue
            checked += 1
            t = float(r.get("created") or 0)
            later = [c for c in att if t < c["created"] <= t + PRED_HORIZON]
            if any(a in (c.get("command") or "") for a in assets for c in later):
                hits += 1
    anticipation = {
        "assessments": len(assess),
        "with_prediction": len(with_pred),
        "with_intent": sum(1 for r in assess if r.get("intent")),
        "preemptive_interventions": len(preemptive),
        "prediction_checked": checked,
        "prediction_hits": hits,
        "prediction_hit_rate": round(hits / checked, 2) if checked else None,
    }

    return {
        "attacker_stream": bool(att),
        "defense": defense,
        "driver": driver,
        "anticipation": anticipation,
        "target_verification": {
            "executed_action_ids": sorted(executed_ids),
            "target_delivered_action_ids": sorted(target_delivered_ids),
            "linked_reobserved_action_ids": sorted(linked_reobserved_ids),
            "final_reobserved_action_ids": sorted(final_reobserved_ids),
            "deliveries": [{
                "action_id": o.get("action_id"), "status": o.get("status"),
                "evidence_id": o.get("evidence_id"), "native_object_id": o.get("native_object_id"),
                "verified_at": o.get("verified_at"),
            } for o in delivery_observations],
            "containments": [{
                "action_id": o.get("action_id"), "status": o.get("status"),
                "evidence_id": o.get("evidence_id"), "verified_at": o.get("verified_at"),
            } for o in containment_observations],
        },
        "attack": {
            "commands": len(att),
            "duration_s": round(duration, 1),
            "commands_per_min": round(len(att) / (duration / 60), 2) if duration > 0 else None,
        },
        "detection": {
            "time_to_first_detection_s": round(ttd, 1) if ttd is not None else None,
            "confidence_threshold": conf_threshold,
            "interventions": len(successful_dcmds),
            "planned_interventions": len(interventions),
            "no_intervention_turns": len(decisions) - len(interventions),
        },
        "honeytokens": honey,
        "intervention_impact": {
            "first_intervention_s": round(first_iv_ts - t0, 1) if (first_iv_ts and t0) else None,
            "attacker_error_rate_before": None if before is None else round(before, 2),
            "attacker_error_rate_after": None if after is None else round(after, 2),
        },
    }


def run_summary(events) -> list[dict]:
    """Compact view of the run manifests in scope (see gateway run_manifest)."""
    out, seen = [], set()
    for e in streams.runs_of(events):
        r = e.get("run") or {}
        if not r or "policy" not in r:
            out.append({"policy": None})
            continue
        sig = (r["policy"].get("short"), r.get("model", {}).get("model_id"), r.get("scenario", {}).get("short"),
               r.get("mechanism", {}).get("short"))
        if sig in seen:   # v0.14: one agent_start per driver turn -> show each configuration once
            continue
        seen.add(sig)
        out.append({"ts": e.get("ts"), "policy": r["policy"].get("short"), "policy_label": r["policy"].get("label"),
                    "model_id": r.get("model", {}).get("model_id"), "endpoint": r.get("model", {}).get("endpoint_host"),
                    "scenario": r.get("scenario", {}).get("name"), "scenario_sha": r.get("scenario", {}).get("short"),
                    "gateway": r.get("mechanism", {}).get("gateway"), "mechanism_sha": r.get("mechanism", {}).get("short")})
    return out


def select(path: str, session: str | None, since, until, everything: bool):
    p = Path(path)
    if p.is_file():
        return load(p), f"file {p.name}"
    events = streams.merge(p)
    if since is not None or until is not None:
        return (streams.with_run_context(events, streams.window(events, since, until), since),
                f"window {since}..{until}")
    marks = streams.sessions(events)
    if everything or not marks:
        return events, "all streams"
    if session:
        idx = next((i for i, m in enumerate(marks) if m.get("session") == session), None)
        if idx is None:
            sys.exit(f"session {session} not found; known: {', '.join(m.get('session', '?') for m in marks)}")
    else:
        idx = len(marks) - 1
    start = float(marks[idx]["ts"])
    end = float(marks[idx + 1]["ts"]) if idx + 1 < len(marks) else None
    return (streams.with_run_context(events, streams.window(events, start, end), start),
            f"session {marks[idx].get('session')}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", help="runs/ folder (v0.11 streams) or a legacy session .jsonl")
    ap.add_argument("--session")
    ap.add_argument("--since", type=float)
    ap.add_argument("--until", type=float)
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--confidence", type=float, default=0.5)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    events, scope = select(a.path, a.session, a.since, a.until, a.all)
    m = compute(events, a.confidence)
    m["scope"] = scope
    m["runs"] = run_summary(events)
    if a.json:
        print(json.dumps(m, indent=2)); return
    at, de, im, df = m["attack"], m["detection"], m["intervention_impact"], m["defense"]
    print(f"Scope         : {scope} ({len(events)} events)")
    for r in m["runs"] or [{"policy": None}]:
        if r.get("policy") is None:
            print("Run config    : unknown (no agent_start with a run manifest; gateway < 0.13.1)")
            break
        lab = f" [{r['policy_label']}]" if r.get("policy_label") else ""
        print(f"Run config    : policy {r['policy']}{lab}  model {r['model_id'] or '?'}"
              f"  scenario {r['scenario']}@{r['scenario_sha']}  gateway {r['gateway']}")
    if len({r.get("policy") for r in m["runs"]}) > 1:
        print("WARNING       : more than one policy in this scope -- split the runs before comparing")
    print(f"Defense       : {df['observed_events']} observed events ({df['elevated_events']} elevated, "
          f"{df['baseline_events']} baseline skipped), {df['turns']} turns, "
          f"{df['actions']} actions ({df['actions_ok']} ok, {df['actions_refused']} refused)")
    sec = lambda v: "n/a" if v is None else f"{v}s"  # noqa: E731
    print(f"Detection lag : first observed event -> detection {sec(df['first_observed_to_detection_s'])}, "
          f"first elevated -> detection {sec(df['first_elevated_to_detection_s'])}, "
          f"first auth-burst -> detection {sec(df['first_auth_burst_to_detection_s'])}")
    dr = m["driver"]
    if dr["turns_triggered"]:
        print(f"Driver        : {dr['turns_triggered']} turns ({dr['turns_elevated']} elevated, "
              f"{dr['turns_activity']} activity; {dr['turns_failed']} failed), "
              f"trigger latency mean {sec(dr['trigger_latency_mean_s'])} / max {sec(dr['trigger_latency_max_s'])}, "
              f"turn duration mean {sec(dr['turn_duration_mean_s'])}")
    an = m["anticipation"]
    print(f"Anticipation  : {an['with_prediction']}/{an['assessments']} assessments with predicted next steps, "
          f"{an['with_intent']} with intent, {an['preemptive_interventions']} pre-emptive interventions"
          + (f", prediction hit rate {an['prediction_hit_rate']} ({an['prediction_hits']}/{an['prediction_checked']}, "
             f"heuristic: asset mentioned by an attacker command within 300 s)" if an["prediction_checked"] else ""))
    if not m["attacker_stream"]:
        print("Attacker-side : unavailable (no attacker stream in runs/attacker/; "
              "see examples/attacker/README.md)")
        return
    print(f"Attack        : {at['commands']} commands over {at['duration_s']}s "
          f"({at['commands_per_min']} cmd/min)")
    print(f"Detection     : time-to-first-detection "
          f"{sec(de['time_to_first_detection_s'])} (conf>={de['confidence_threshold']}), "
          f"{de['interventions']} interventions, {de['no_intervention_turns']} holds")
    if m["honeytokens"]:
        print("Honeytokens   :")
        for h in m["honeytokens"]:
            hit = f"USED after {h['latency_s']}s ({h['accesses']}x)" if h["accessed"] else "not used"
            print(f"  - {h['value'][:40]:40} {hit}")
    else:
        print("Honeytokens   : none planted")
    print(f"Impact        : attacker error rate {im['attacker_error_rate_before']} -> "
          f"{im['attacker_error_rate_after']} (before -> after first intervention)")


if __name__ == "__main__":
    main()
