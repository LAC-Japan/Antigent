"""Scenario-adapter clean baseline calibration and exact-match filtering.

  python -m unittest discover -s tests -v
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gateway"))
sys.path.insert(0, str(ROOT / "tests"))
import defense_gateway as gw  # noqa: E402
from baseline import CleanBaseline  # noqa: E402
from test_observer import FakeObs, gitea_pair  # noqa: E402


CONFIG = {
    "duration_sec": 60,
    "min_count": 3,
    "min_span_sec": 20,
    "learn": {
        "access-log": ["client", "method", "path"],
        "net-http": ["client", "method", "path"],
        "net-conn": ["client", "dport"],
    },
}
CLIENT = "172.19.0.10"


def learned_profile(source="gitea", kind="access-log", attrs=None):
    attrs = attrs or {"client": CLIENT, "method": "GET", "path": "/user/events"}
    baseline = CleanBaseline(CONFIG, started_at=100)
    for ts in (100, 130, 160):
        baseline.observe({"source": source, "kind": kind, "level": "baseline",
                          "ts": ts, **attrs})
    return baseline.finish(160)


class CleanBaselineTest(unittest.TestCase):
    def test_adapter_owns_calibration_policy(self):
        config = gw.SC["baseline"]
        self.assertEqual(config["duration_sec"], 60)
        self.assertEqual(config["min_count"], 2)   # two 30-second health polls fit in one window
        self.assertEqual(config["min_span_sec"], 20)
        self.assertEqual(config["learn"]["access-log"], ["client", "method", "path"])
        self.assertNotIn("auth-failure", config["learn"])
        self.assertNotIn("fs-change", config["learn"])

    def test_repetition_span_and_exact_match_are_required(self):
        baseline = CleanBaseline(CONFIG, started_at=100)
        event = {"source": "gitea", "kind": "access-log", "level": "baseline",
                 "client": CLIENT, "method": "GET", "path": "/user/events"}
        for ts in (100, 105, 110):
            baseline.observe({"ts": ts, **event})
        baseline.finish(160)
        self.assertEqual(baseline.entries, [])   # repeated, but not over the required time span

        baseline = learned_profile()
        attrs = event | {"ts": 160}
        self.assertTrue(baseline.matches("gitea", "access-log", attrs))
        self.assertFalse(baseline.matches("gitea", "access-log", attrs | {"path": "/api/v1/user"}))
        self.assertFalse(baseline.matches("gitea", "access-log", attrs | {"method": "POST"}))
        self.assertFalse(baseline.matches("gitea", "access-log", attrs | {"client": "10.0.0.8"}))
        self.assertFalse(baseline.matches("jenkins", "access-log", attrs))
        self.assertFalse(baseline.matches("gitea", "net-http", attrs))

    def test_profile_round_trip_preserves_filter(self):
        profile = learned_profile().to_dict()
        restored = CleanBaseline.from_dict(profile)
        event = {"client": CLIENT, "method": "GET", "path": "/user/events"}
        self.assertTrue(restored.matches("gitea", "access-log", event))
        self.assertEqual(restored.entries[0]["count"], 3)
        self.assertNotIn("summary", restored.entries[0])
        self.assertNotIn("raw", restored.entries[0])

    def test_observer_filters_learned_route_without_hiding_new_route(self):
        o = FakeObs(logs="\n".join(sum((gitea_pair(i, "/user/events") for i in range(12)), [])))
        o.load_baseline(learned_profile().to_dict())
        o._collect_logs("gitea", "gitea", "access-log")
        learned = [e for e in o.out if e["kind"] == "access-log"]
        self.assertEqual(len(learned), 12)   # Completed lines only; Started remains quiet
        self.assertTrue(all(e["level"] == "baseline" for e in learned))
        self.assertTrue(all(e.get("baseline_reason") == "clean_calibration" for e in learned))
        self.assertFalse(any(e["level"] == "elevated" for e in o.out))

        before = len(o.out)
        o._logs = "\n".join(gitea_pair(30, "/qa/unlearned", "404"))
        o._collect_logs("gitea", "gitea", "access-log")
        new = o.out[before:]
        self.assertEqual([(e["kind"], e["level"]) for e in new], [("access-log", "raw")])
        self.assertEqual(new[0]["method"], "GET")
        self.assertEqual(new[0]["path"], "/qa/unlearned")

    def test_unlearned_routes_from_learned_client_still_burst(self):
        lines = sum((gitea_pair(i, f"/qa/unknown/{i}", "404") for i in range(12)), [])
        o = FakeObs(logs="\n".join(lines))
        o.load_baseline(learned_profile().to_dict())
        o._collect_logs("gitea", "gitea", "access-log")
        self.assertIn("recon-burst", {e["kind"] for e in o.out if e["level"] == "elevated"})
        self.assertIn("error-burst", {e["kind"] for e in o.out if e["level"] == "elevated"})
        self.assertEqual(len([e for e in o.out if e["kind"] == "access-log" and e["level"] == "raw"]), 12)

    def test_finish_clears_calibration_burst_windows(self):
        o = FakeObs(logs="\n".join(sum((gitea_pair(i, f"/qa/pre/{i}", "404") for i in range(9)), [])))
        o.begin_baseline(CONFIG, 60)
        o.baseline = True
        o._collect_logs("gitea", "gitea", "access-log")
        self.assertTrue(o.req or o.err)
        o.finish_baseline()
        self.assertFalse(o.req)
        self.assertFalse(o.err)
        self.assertFalse(o.fail)

        o.baseline = False
        o._logs = "\n".join(gitea_pair(20, "/qa/post", "404"))
        o._collect_logs("gitea", "gitea", "access-log")
        self.assertFalse(any(e["level"] == "elevated" for e in o.out))


if __name__ == "__main__":
    unittest.main()
