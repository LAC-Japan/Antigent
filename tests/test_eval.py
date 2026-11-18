"""Self-test for the event log, metrics and attacker-log validator (no Docker, no target).

  python -m unittest discover -s tests -v
"""
import io
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))
import metrics  # noqa: E402
import streams  # noqa: E402

RUN = ROOT / "fixtures" / "sample-run"


class EvalTest(unittest.TestCase):
    def test_full_run(self):
        events, scope = metrics.select(str(RUN), None, None, None, False)
        self.assertEqual(scope, "session s1")
        m = metrics.compute(events)
        self.assertTrue(m["attacker_stream"])
        self.assertEqual(m["attack"]["commands"], 4)
        self.assertEqual(m["detection"]["interventions"], 1)
        self.assertEqual(m["detection"]["no_intervention_turns"], 1)
        self.assertEqual(m["detection"]["time_to_first_detection_s"], 30.0)   # T+40 - T+10
        self.assertEqual(m["defense"]["actions_refused"], 1)
        self.assertEqual(m["defense"]["first_auth_burst_to_detection_s"], 10.0)
        h = m["honeytokens"][0]
        self.assertTrue(h["accessed"])
        self.assertEqual(h["latency_s"], 39.0)                                 # T+80 - T+41

    def test_failed_or_note_action_is_not_intervention(self):
        base = [
            {"type": "record", "record": {"kind": "decision", "created": 10,
                                           "strategy": "deception-honeytoken"}},
            {"type": "command", "command": {"id": "n1", "side": "defender", "via": "gateway",
                                             "label": "note", "command": "# note", "created": 11,
                                             "status": "done", "exit_code": 0}},
            {"type": "command", "command": {"id": "d1", "side": "defender", "via": "gateway",
                                             "label": "exec", "command": "[gitea] nope", "created": 12,
                                             "status": "done", "exit_code": 1}},
        ]
        m = metrics.compute(base)
        self.assertEqual(m["detection"]["interventions"], 0)
        self.assertEqual(m["detection"]["planned_interventions"], 1)
        self.assertEqual(m["defense"]["actions"], 1)
        self.assertEqual(m["defense"]["actions_ok"], 0)
        self.assertIsNone(m["intervention_impact"]["first_intervention_s"])

    def test_honeytoken_read_follow_and_reobservation_are_distinct(self):
        events = [
            {"type": "command", "command": {"id": "d1", "side": "defender", "via": "gateway",
                                             "label": "exec", "command": "[gitea] plant", "created": 10,
                                             "status": "done", "exit_code": 0}},
            {"type": "record", "record": {"kind": "marker", "created": 10, "value": "SECRET-MARKER",
                                           "action_id": "d1"}},
            {"type": "command", "command": {"id": "a1", "side": "attacker", "command": "cat deploy.env",
                                             "created": 20, "stdout": "SECRET-MARKER", "stderr": ""}},
            {"type": "turn_accepted", "turn": 2, "reason": "reobservation",
             "reobserved_action_ids": ["d1"]},
        ]
        h = metrics.compute(events)["honeytokens"][0]
        self.assertTrue(h["delivered"])
        self.assertTrue(h["read"])
        self.assertFalse(h["followed"])
        self.assertTrue(h["reobserved"])
        self.assertIsNone(h["decision_changed"])

    def test_honeytoken_follow_does_not_imply_read(self):
        events = [
            {"type": "record", "record": {"kind": "marker", "created": 10, "value": "SECRET-MARKER",
                                           "action_id": "d1"}},
            {"type": "command", "command": {"id": "d1", "side": "defender", "via": "gateway",
                                             "label": "exec", "command": "[gitea] plant", "created": 10,
                                             "status": "done", "exit_code": 0}},
            {"type": "command", "command": {"id": "a1", "side": "attacker",
                                             "command": "use SECRET-MARKER", "created": 20}},
        ]
        h = metrics.compute(events)["honeytokens"][0]
        self.assertFalse(h["read"])
        self.assertTrue(h["followed"])

    def test_briefing_and_unsubmitted_turn_metrics(self):
        events = [
            {"type": "trigger", "turn": 0, "reason": "briefing", "ts": 1},
            {"type": "turn_end", "turn": 0, "exit_code": 0, "duration": 1},
            {"type": "trigger", "turn": 1, "reason": "elevated", "ts": 10, "first_elevated_ts": 9},
            {"type": "turn_end", "turn": 1, "exit_code": 0, "submitted": False, "duration": 2},
        ]
        d = metrics.compute(events)["driver"]
        self.assertEqual(d["turns_triggered"], 1)
        self.assertEqual(d["turns_failed"], 1)
        self.assertEqual(d["turns_unsubmitted"], 1)

    def test_run_manifest(self):
        """The run configuration (policy / model / scenario) travels with the session window."""
        events, _ = metrics.select(str(RUN), None, None, None, False)
        runs = metrics.run_summary(events)
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["policy"], "aaaaaaaaaaaa")
        self.assertEqual(runs[0]["model_id"], "Qwen/Qwen2.5-7B-Instruct")
        self.assertEqual(runs[0]["scenario_sha"], "bbbbbbbbbbbb")

    def test_defense_only(self):
        """The defense plane alone (no attacker stream) still yields defender-side metrics."""
        tmp = Path(tempfile.mkdtemp())
        try:
            shutil.copytree(RUN / "defense", tmp / "defense")
            m = metrics.compute(streams.merge(tmp))
            self.assertFalse(m["attacker_stream"])
            self.assertEqual(m["defense"]["turns"], 2)
            self.assertEqual(m["defense"]["observed_events"], 2)
        finally:
            shutil.rmtree(tmp)


if __name__ == "__main__":
    unittest.main()
