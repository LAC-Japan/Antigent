"""v0.15.1 observer behaviour: ANSI Gitea router logs, quiet lines, docker diff filtering.
  python -m unittest discover -s tests -v
"""
import sys
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gateway"))
import defense_gateway as gw  # noqa: E402

E = "\x1b"


def gitea_pair(i, path, status="200", ip="172.19.0.10"):
    st = f"2026-11-15T06:34:{i:02d}.000000000Z"
    return [
        f"{st} {E}[36m2026/11/15 06:34:19 {E}[0mStarted {E}[34mGET{E}[0m {E}[1m{path}{E}[0m for {E}[1m{ip}:{43000 + i}{E}[0m",
        f"{st} {E}[36m2026/11/15 06:34:19 {E}[0mCompleted {E}[34mGET{E}[0m {E}[1m{path}{E}[0m {E}[32m{status}{E}[0m {E}[32mOK{E}[0m in {E}[1m24ms{E}[0m",
    ]


class FakeObs(gw.Observer):
    def __init__(self, logs="", diff=""):
        self.out = []
        super().__init__(sink=self.out.append)
        self._internal_at = 1e18   # no docker in tests: empty internal set
        self._logs, self._diff = logs, diff

    def _docker(self, args, timeout=15):
        return (0, self._diff, "") if args[0] == "diff" else (0, self._logs, "")


class ObserverTest(unittest.TestCase):
    def test_gitea_ansi_router_log(self):
        lines = []
        for i in range(12):
            lines += gitea_pair(i, f"/api/v1/repos/Wonderland/r{i}", "404" if i < 6 else "200")
        o = FakeObs(logs="\n".join(lines))
        o._collect_logs("gitea", "gitea", "access-log")
        kinds = [e["kind"] for e in o.out]
        self.assertIn("new-source", kinds)
        self.assertIn("recon-burst", kinds)
        self.assertIn("error-burst", kinds)          # 404s attributed via the Started line
        logs = [e for e in o.out if e["kind"] == "access-log"]
        self.assertEqual(len(logs), 12)               # Started lines are quiet
        self.assertFalse(any("\x1b" in e["summary"] for e in logs))
        self.assertTrue(all(e["summary"].startswith("2026/11/15") for e in logs))

    def test_diff_ignore_parent_and_self(self):
        diff = "C /run\nA /run/sshd.pid\nC /var\nC /var/www\nA /var/www/.env\nA /tmp/x.sh\n"
        o = FakeObs(diff=diff)
        o._collect_diff("prod", "prod", "fs-change", gw.ROLES["prod"]["sensors"][0]["_ignore"])
        self.assertEqual([e["summary"] for e in o.out], ["A /var/www/.env", "A /tmp/x.sh"])
        self.assertTrue(all(e["level"] == "elevated" for e in o.out))
        o2 = FakeObs(diff="A /var/www/decoy.txt\n")
        o2.self_active = lambda role: True
        o2._collect_diff("prod", "prod", "fs-change", [])
        self.assertEqual(o2.out[0]["level"], "raw")
        self.assertEqual(o2.out[0]["cause"], "antigent")

    def test_old_lines_never_elevated(self):
        old = [f"2026-11-15T06:00:{i:02d}.0Z Failed authentication attempt for bad from 172.19.0.10:5{i}: x"
               for i in range(3)]
        old += sum((gitea_pair(i, f"/r{i}") for i in range(8)), [])
        o = FakeObs(logs="\n".join(old))
        o.baseline = True                       # sensor's first cycle
        o.collect(["gitea"])
        o.baseline = False
        o._logs = "\n".join(sum((gitea_pair(i + 20, f"/n{i}") for i in range(3)), []))
        o.collect(["gitea"])
        o._flush_auth(force=True)
        self.assertFalse([e for e in o.out if e["level"] == "elevated"], [e["kind"] for e in o.out])

    def test_late_sensor_is_baseline(self):
        o = FakeObs(logs="\n".join(sum((gitea_pair(i, f"/r{i}") for i in range(12)), [])))
        o.collect(["gitea"])                    # first read of this sensor, global baseline already over
        self.assertTrue(o.out and all(e["level"] == "baseline" for e in o.out))

    def test_internal_sensor_marks_events(self):
        import driver
        o = FakeObs(logs="2026-11-15T08:00:00Z j.b.MultiBranchProject BranchIndexing completed: SUCCESS\n"
                         "2026-11-15T08:00:01Z another jenkins build line\n")
        o._collect_logs("jenkins", "jenkins", "build-log", internal=True)
        self.assertTrue(o.out and all(e.get("internal") and e["kind"] == "build-log" for e in o.out))
        self.assertFalse(any(e.get("client") for e in o.out))
        self.assertFalse(any(driver.is_activity(e) for e in o.out))   # internal never triggers activity

    def test_pull_request_builds_surface_from_the_internal_build_log(self):
        # The scenario's own surface rules: a PR build names the exact WorkflowJob that containment
        # needs, so it must reach Antigent (elevated) while branch indexing stays internal.
        import json
        sc = json.loads((ROOT / "scenarios" / "cicd-goat" / "scenario.json").read_text())
        rules = [(gw.re.compile(r["pattern"]), r["kind"]) for r in sc["roles"]["jenkins"]["sensors"][0]["surface"]]
        self.assertIn("pipeline-run", sc["triggers"]["kinds"])
        o = FakeObs(logs=(
            "2026-11-18T07:13:00Z INFO j.b.MultiBranchProject$BranchIndexing#run: wonderland-caterpillar-test #1 branch indexing action completed\n"
            "2026-11-18T07:13:01Z INFO o.j.p.g.GiteaNotifier$JobScheduledListener$1#run: Notifying pull request pending build wonderland-caterpillar-test/PR-1\n"
            "2026-11-18T07:13:02Z INFO o.j.p.workflow.job.WorkflowRun#finish: wonderland-caterpillar-test/PR-1 #1 completed: FAILURE\n"
            "2026-11-18T07:13:03Z INFO o.j.p.workflow.job.WorkflowRun#finish: wonderland-caterpillar-prod/main #1 completed: SUCCESS\n"))
        with unittest.mock.patch.dict(gw.SC, {"_trigger_kinds": set(sc["triggers"]["kinds"])}):
            o._collect_logs("jenkins", "jenkins", "build-log", internal=True, surface=rules)
        shown = [e for e in o.out if not e.get("internal")]
        self.assertEqual([e["kind"] for e in shown], ["pipeline-run", "pipeline-run"])
        self.assertTrue(all(e["job"] == "wonderland-caterpillar-test/PR-1" for e in shown))
        self.assertEqual(shown[1]["result"], "FAILURE")
        self.assertTrue(all(e["level"] == "elevated" for e in shown))
        hidden = [e["summary"] for e in o.out if e.get("internal")]
        self.assertEqual(len(hidden), 2)          # branch indexing and the main-branch build stay internal

    def test_scenario_request_rule_reports_repository_reads_at_once(self):
        # The scenario marks repository reads (clone/fetch, API file reads) as `repo-read`, an
        # elevated kind: one event per client and repository, internal clients excluded.
        import json
        sc = json.loads((ROOT / "scenarios" / "cicd-goat" / "scenario.json").read_text())
        compiled = [{"kind": r["kind"], "path": gw.re.compile(r["path"]), "method": None, "label": r["label"]}
                    for r in sc["request_rules"]]
        lines = (gitea_pair(1, "/Wonderland/caterpillar.git/info/refs?service=git-upload-pack", ip="172.24.0.2")
                 + gitea_pair(2, "/Wonderland/caterpillar.git/git-upload-pack", ip="172.24.0.2")
                 + gitea_pair(3, "/api/v1/repos/Wonderland/caterpillar/contents/Jenkinsfile", ip="172.24.0.2")
                 + gitea_pair(4, "/api/v1/version", ip="172.24.0.2")
                 + gitea_pair(5, "/Wonderland/caterpillar.git/git-upload-pack", ip="172.19.0.5"))
        o = FakeObs(logs="\n".join(lines))
        o.primed = set()
        o._collect_logs("gitea", "gitea", "access-log")      # first read = baseline, ignored
        o.out.clear()
        o.baseline = False
        o._internal = {"172.19.0.5"}
        with unittest.mock.patch.dict(gw.SC, {"_request_rules": compiled,
                                              "_trigger_kinds": set(sc["triggers"]["kinds"])}):
            o.seen.clear()
            o._collect_logs("gitea", "gitea", "access-log")
        reads = [e for e in o.out if e["kind"] == "repo-read"]
        # clone (info/refs + upload-pack) = one event; the API file read of the same repo is
        # another rule's event; /api/v1/version and the internal client's fetch are not reads
        self.assertEqual([(e["target"], e["summary"].split(":")[0]) for e in reads],
                         [("Wonderland/caterpillar", "repository clone/fetch"),
                          ("Wonderland/caterpillar", "repository file read")])
        self.assertTrue(all(e["level"] == "elevated" and e["client"] == "172.24.0.2" for e in reads))

    def test_internal_service_not_a_client(self):
        lines = sum((gitea_pair(i, f"/api/v1/repos/Wonderland/r{i}", ip="172.19.0.5") for i in range(12)), [])
        o = FakeObs(logs="\n".join(lines))
        o._internal, o._internal_at = {"172.19.0.5"}, 1e18   # e.g. Jenkins scanning Gitea
        o._collect_logs("gitea", "gitea", "access-log")
        self.assertEqual({e["kind"] for e in o.out}, {"access-log"})
        self.assertTrue(all(e["level"] == "raw" for e in o.out))
        self.assertTrue(all(e.get("internal") and e.get("client") == "172.19.0.5" for e in o.out))
        import driver
        self.assertFalse(any(driver.is_activity(e) for e in o.out))   # no activity turn
        o2 = FakeObs(logs="\n".join(gitea_pair(1, "/x", ip="172.19.0.99")))
        o2._collect_logs("gitea", "gitea", "access-log")
        self.assertTrue(any(driver.is_activity(e) for e in o2.out))    # external client counts

    def test_gitea_runs_as_root(self):
        # v0.15.8: gitea actions run as root (no exec_user) for filesystem freedom.
        self.assertIsNone(gw.ROLES["gitea"].get("exec_user"))

    def test_observe_excludes_internal(self):
        # v0.16.4: observe_events returns external-client events only; the range's own internal
        # services are excluded by default, so the agent cannot cite them as attacker evidence.
        import tempfile, json as _j
        from pathlib import Path as _P
        d = tempfile.mkdtemp()
        p = _P(d) / "sensor.jsonl"
        rows = [
            {"index": 1, "source": "gitea", "level": "elevated", "kind": "new-source", "summary": "attacker"},
            {"index": 2, "source": "gitea", "level": "raw", "kind": "access-log", "internal": True, "summary": "CI scan"},
            {"index": 3, "source": "gitea", "level": "raw", "kind": "access-log", "summary": "attacker clone"},
        ]
        with open(p, "w") as f:
            for r in rows:
                f.write(_j.dumps({"type": "observed", "event": r}) + "\n")
        old = gw.SENSOR_STREAM
        try:
            gw.SENSOR_STREAM = p
            r = gw.observe_from_stream({"since_index": 0})
            idx = {e["index"] for e in r["events"]}
            self.assertEqual(idx, {1, 3})                 # internal #2 dropped
            self.assertEqual(r.get("internal_skipped"), 1)
            r2 = gw.observe_from_stream({"since_index": 0, "include_internal": True})
            self.assertEqual({e["index"] for e in r2["events"]}, {1, 2, 3})
        finally:
            gw.SENSOR_STREAM = old

    def test_observe_pagination_never_skips_events(self):
        import tempfile, json as _j
        from pathlib import Path as _P
        p = _P(tempfile.mkdtemp()) / "sensor.jsonl"
        rows = [
            {"index": i, "source": "gitea" if i != 5 else "prod",
             "level": "elevated" if i in (2, 4) else "raw",
             "kind": "new-source" if i in (2, 4) else "access-log"}
            for i in range(1, 6)
        ]
        with open(p, "w") as f:
            for row in rows:
                f.write(_j.dumps({"type": "observed", "event": row}) + "\n")
        old = gw.SENSOR_STREAM
        try:
            gw.SENSOR_STREAM = p
            pages, since = [], 0
            for _ in range(4):
                result = gw.observe_from_stream({"since_index": since, "limit": 2})
                pages.append([e["index"] for e in result["events"]])
                self.assertEqual(result["next_since_index"], result["max_index"])
                self.assertEqual(result["scan_max_index"], 5)
                self.assertEqual(result["dropped"], 0)
                since = result["next_since_index"]
                if not result["truncated"]:
                    break
            self.assertEqual(pages, [[1, 2], [3, 4], [5]])
            self.assertEqual(since, 5)
        finally:
            gw.SENSOR_STREAM = old

    def test_observe_pagination_with_role_filter(self):
        import tempfile, json as _j
        from pathlib import Path as _P
        p = _P(tempfile.mkdtemp()) / "sensor.jsonl"
        with open(p, "w") as f:
            for i, role in enumerate(("gitea", "jenkins", "gitea", "gitea"), 1):
                row = {"index": i, "source": role, "level": "elevated", "kind": "new-source"}
                f.write(_j.dumps({"type": "observed", "event": row}) + "\n")
        old = gw.SENSOR_STREAM
        try:
            gw.SENSOR_STREAM = p
            first = gw.observe_from_stream({"roles": ["gitea"], "limit": 2})
            second = gw.observe_from_stream({"roles": ["gitea"], "limit": 2,
                                             "since_index": first["next_since_index"]})
            self.assertEqual([e["index"] for e in first["events"]], [1, 3])
            self.assertEqual([e["index"] for e in second["events"]], [4])
            self.assertFalse(second["truncated"])
        finally:
            gw.SENSOR_STREAM = old


if __name__ == "__main__":
    unittest.main()


class SubmitTurnTest(unittest.TestCase):
    """submit_turn: tolerant parsing of weak-model output, one submit per turn, typed
    operations only (no raw commands), and a persistent reservation for each attempt."""

    def setUp(self):
        import tempfile
        self.d = tempfile.mkdtemp()
        gw.DEFENSE_LOG = __import__("pathlib").Path(self.d) / "d.jsonl"
        gw.DRIVER_TURN = 1
        gw.DRIVER_REASON = ""
        gw.REOBSERVE_ACTION_IDS = []
        gw._SUBMITTED_TURN = None
        gw._ASSESSED_TURN = None
        gw._GATE = None

    def rows(self):
        import json as _j
        return [_j.loads(line) for line in open(gw.DEFENSE_LOG)]

    def test_stringified_assessment(self):
        r = gw.do_submit_turn({
            "assessment": '{"stage": "Reconnaissance", "intent": "x", "confidence": 0.7}',
            "decision": '{"strategy": "no_intervention", "preempts": 0}',
            "actions": []})
        self.assertTrue(r.get("ok"))
        kinds = [row["record"]["kind"] for row in self.rows() if "record" in row]
        self.assertIn("assessment", kinds)
        self.assertIn("decision", kinds)

    def test_one_submit_per_turn(self):
        gw.do_submit_turn({"assessment": {"stage": "x"}, "decision": {}, "actions": []})
        r2 = gw.do_submit_turn({"assessment": {"stage": "y"}, "decision": {}, "actions": []})
        self.assertEqual(r2.get("status"), "already_submitted")

    def test_raw_command_is_refused_and_locks_the_turn(self):
        r = gw.do_submit_turn({"assessment": {}, "decision": {"strategy": "d"},
                               "actions": [{"role": "jenkins", "cmd": "echo 1", "marker": "AKIA-1"}]})
        self.assertEqual([a["status"] for a in r["actions"]], ["refused"])
        self.assertFalse(r["retry"])
        self.assertIn("typed_operation_required", r["protocol_violations"])
        self.assertFalse(any((row.get("record") or {}).get("kind") == "marker" for row in self.rows()))
        r2 = gw.do_submit_turn({"assessment": {}, "decision": {}, "actions": []})
        self.assertEqual(r2.get("status"), "already_submitted")

    def test_note_cannot_plant_marker(self):
        for action in ({"note": "not delivered", "marker": "AKIA-NOTE"},
                       {"note": "not delivered", "cmd": "echo no", "marker": "AKIA-NOTE"}):
            r = gw.run_action(action)
            self.assertEqual(r["status"], "refused")
        gw.do_submit_turn({"assessment": {}, "decision": {"strategy": "deception"},
                           "actions": [{"note": "not delivered", "marker": "AKIA-NOTE"}]})
        rows = self.rows()
        self.assertFalse(any((r.get("record") or {}).get("kind") == "marker" for r in rows))
        accepted = next(r for r in rows if r.get("type") == "turn_accepted")
        self.assertFalse(accepted["intervened"])

    def test_reobservation_drops_new_actions(self):
        gw.DRIVER_REASON = "reobservation"
        r = gw.do_submit_turn({
            "assessment": {}, "decision": {"strategy": "deception"},
            "actions": [{"role": "gitea", "operation": "gitea_repo_file"}],
        })
        self.assertIn("reobservation_action", r["protocol_violations"])
        self.assertFalse(any(row.get("type") == "command" for row in self.rows()))

    def test_typed_action_is_reserved_executed_and_correlated(self):
        from unittest import mock

        class Adapter:
            def execute(self, action, action_id):
                obs = {"schema_version": "delivery_observation_v1", "status": "verified",
                       "evidence_id": "e" * 64}
                return {"role": "gitea", "label": "exec", "command": "[gitea] operation=gitea_repo_file",
                        "marker": "", "stdout": "", "stderr": "", "exit_code": 0, "duration": 0.1,
                        "status": "done", "observations": [{"type": "delivery_observation", "observation": obs}],
                        "effect": None}

        action = {"role": "gitea", "operation": "gitea_repo_file", "repository": "o/r", "ref": "main",
                  "path": "a/b.txt", "content": "X AKIA-ID", "marker": "AKIA-ID", "evidence": [3]}
        with mock.patch.object(gw, "typed_adapter", return_value=Adapter()):
            r = gw.do_submit_turn({"assessment": {}, "decision": {"strategy": "deception"}, "actions": [action]})
        action_id = r["actions"][0]["id"]
        rows = self.rows()
        command = next(r["command"] for r in rows if r.get("type") == "command")
        marker = next(r["record"] for r in rows if (r.get("record") or {}).get("kind") == "marker")
        accepted = next(r for r in rows if r.get("type") == "turn_accepted")
        self.assertEqual(command["id"], action_id)
        self.assertEqual(marker["action_id"], action_id)
        self.assertEqual(accepted["target_delivered_action_ids"], [action_id])
        self.assertTrue(accepted["intervened"])
        self.assertIsNotNone(command["reservation_id"])

