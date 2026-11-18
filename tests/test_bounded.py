"""Offline regression tests for the typed gateway, gate and CI/CD adapter."""
from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "gateway"))
sys.path.insert(0, str(ROOT / "scenarios" / "cicd-goat"))
os.environ.setdefault("ANTIGENT_SCENARIO", str(ROOT / "scenarios" / "cicd-goat"))

import adapter  # noqa: E402
import defense_gateway as gw  # noqa: E402
from intervention_gate import CONTEXT_PROTOCOL_ID  # noqa: E402
from intervention_gate import InterventionGate as _InterventionGate  # noqa: E402


def InterventionGate(*args, **kwargs):  # noqa: N802 - the scenario adapter declares the targets
    kwargs.setdefault("target_fields", adapter.OPERATION_TARGETS)
    return _InterventionGate(*args, **kwargs)


def gitea_action(path="deploy/environment.json", content="TOKEN=unused\n"):
    return {
        "role": "gitea", "operation": "gitea_repo_file",
        "repository": "wonderland/ci", "ref": "main", "path": path,
        "content": content, "marker": "unused", "evidence": [7],
    }


class BoundedGateTest(unittest.TestCase):
    def test_no_fixed_limit_but_safety_rules_hold(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = InterventionGate(Path(tmp) / "state.json")
            for turn in range(1, 5):
                action_id = f"a{turn:09d}"
                reserved = gate.reserve(gitea_action(f"deploy/file-{turn}.json"), action_id, turn)
                self.assertTrue(reserved["allowed"])
                gate.complete(action_id, exit_code=1)
                if turn < 4:
                    gate.link_reobservation([action_id], turn + 10)
            self.assertEqual(len(gate.snapshot()["reservations"]), 4)
            self.assertIsNone(gate.snapshot()["max_interventions"])
            self.assertEqual(gate.snapshot()["protocol_id"], CONTEXT_PROTOCOL_ID)
            pending = gate.reserve(gitea_action("deploy/pending.json"), "b000000005", 5)
            self.assertEqual(pending["reason"], "reobservation_pending")
            gate.link_reobservation(["a000000004"], 14)
            duplicate = gate.reserve(
                gitea_action("deploy/file-1.json", content="TOKEN=changed\n"), "b000000006", 6,
            )
            self.assertEqual(duplicate["reason"], "duplicate_operation")
            first_six = gate.reserve(gitea_action("deploy/other.json"), "b000000007", 6)
            self.assertTrue(first_six["allowed"])
            same_turn = gate.reserve(gitea_action("deploy/another.json"), "b000000008", 6)
            self.assertEqual(same_turn["reason"], "turn_duplicate")
            state = json.dumps(gate.snapshot())
            self.assertNotIn("TOKEN=changed", state)
            self.assertNotIn("deploy/file-1.json", state)

    def test_failed_attempt_is_not_returned_and_same_turn_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = InterventionGate(Path(tmp) / "state.json")
            action = gitea_action()
            first = gate.reserve(action, "a000000001", 1)
            self.assertTrue(first["allowed"])
            same_turn = gate.reserve(action, "b000000002", 1)
            self.assertEqual(same_turn["reason"], "turn_duplicate")
            gate.complete("a000000001", exit_code=1)
            gate.link_reobservation(["a000000001"], 2)
            retry = gate.reserve(gitea_action(), "c000000003", 3)
            self.assertEqual(retry["reason"], "duplicate")
            self.assertEqual(gate.snapshot()["reservations"][0]["status"], "completed")

    def test_unknown_operation_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = InterventionGate(Path(tmp) / "state.json")
            r = gate.reserve({"role": "gitea", "operation": "rm_rf"}, "a000000001", 1)
            self.assertEqual(r["reason"], "unsupported_operation")

    def test_canonical_native_repository_identity_is_used_for_dedup(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = InterventionGate(Path(tmp) / "state.json")
            observed = gitea_action()
            observed["repository"] = "Wonderland/ci"
            self.assertTrue(gate.reserve(observed, "a000000001", 1)["allowed"])
            gate.complete("a000000001", exit_code=0, effect={
                "operation": "gitea_repo_file",
                "target": {"repository": "wonderland/ci", "ref": "main", "path": "deploy/environment.json"},
            })
            gate.link_reobservation(["a000000001"], 2)
            canonical = gitea_action()
            canonical["evidence"] = [8]
            duplicate = gate.reserve(canonical, "b000000002", 3)
            self.assertEqual(duplicate["reason"], "duplicate_operation")

    def test_missing_state_with_prior_exec_fails_closed_and_final_link_is_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            defense = root / "defense.jsonl"
            defense.write_text(json.dumps({
                "type": "command", "command": {"side": "defender", "label": "exec"},
            }) + "\n", encoding="utf-8")
            gate = InterventionGate(root / "missing.json", defense_log=defense)
            with self.assertRaises(RuntimeError):
                gate.initialize()

            state_gate = InterventionGate(root / "state.json")
            state_gate.reserve(gitea_action(), "a000000001", 1)
            state_gate.link_reobservation(["a000000001"], 2)
            state_gate.link_reobservation(["a000000001"], 3, final=True)
            row = state_gate.snapshot()["reservations"][0]
            self.assertEqual(row["reobservation_turn"], 2)
            self.assertEqual(row["final_reobservation_turn"], 3)


class BoundedAdapterTest(unittest.TestCase):
    def test_gitea_delivery_and_later_attacker_commit_protection(self):
        before, defense, attacker = "1" * 40, "2" * 40, "3" * 40

        class Exec:
            def __init__(self):
                self.head = defense

            def __call__(self, argv, timeout=60):
                del timeout
                script = argv[-1]
                if 'find "$root" -mindepth 2 -maxdepth 2' in script:
                    return SimpleNamespace(
                        returncode=0,
                        stdout="/data/git/repositories/wonderland/ci.git\n",
                        stderr="",
                    )
                if 'printf "before=%s\\n" "$before"' in script:
                    return SimpleNamespace(returncode=0, stdout=f"before={before}\n", stderr="")
                if 'printf "after=%s\\n" "$commit"' in script:
                    env = dict(arg.split("=", 1) for arg in argv if arg.startswith("GITEA_"))
                    assert env.get("GITEA_PUSHER_ID") == "1"
                    assert env.get("GITEA_PUSHER_NAME") == "red_queen"
                    return SimpleNamespace(returncode=0, stdout=f"after={defense}\n", stderr="")
                if "gitea admin user list --admin" in script:
                    return SimpleNamespace(
                        returncode=0, stdout="ID Username Email IsActive\n1 red_queen queen@localhost true\n", stderr=""
                    )
                if 'rev-parse --verify "refs/heads/$ANTIGENT_REF"' in script:
                    return SimpleNamespace(returncode=0, stdout=f"{self.head}\n", stderr="")
                if 'show "$ANTIGENT_DEFENSE:$ANTIGENT_PATH"' in script:
                    return SimpleNamespace(returncode=0, stdout="TOKEN=unused\n", stderr="")
                return SimpleNamespace(returncode=0, stdout="", stderr="")

        native = adapter.CicdGoatAdapter(exec_fn=Exec())
        observed_action = gitea_action()
        observed_action["repository"] = "Wonderland/ci"
        result = native.execute(observed_action, "a000000001")
        delivery = result["observations"][0]["observation"]
        self.assertEqual(delivery["status"], "verified")
        self.assertEqual(delivery["native_object_id"], defense)
        self.assertEqual(result["effect"]["target"]["repository"], "wonderland/ci")
        self.assertNotIn("unused", json.dumps(result["effect"]))
        self.assertNotIn("deploy/environment.json", json.dumps(delivery))

        # D -> attacker A: recovery must not reset A to the pre-defense snapshot.
        native.exec_fn.head = attacker
        recovery = native._recover_gitea(result["effect"])
        self.assertEqual(recovery["status"], "conflict")
        self.assertTrue(recovery["residual_effect"])
        self.assertFalse(recovery["restored_before_hash"])

    def test_nested_gitea_defense_commits_are_recovered_newest_first(self):
        before, first, second = "1" * 40, "2" * 40, "3" * 40

        class Exec:
            def __init__(self):
                self.head = second

            def __call__(self, argv, timeout=60):
                del timeout
                script = argv[-1]
                env = dict(
                    arg.split("=", 1) for arg in argv
                    if arg.startswith("ANTIGENT_")
                )
                if 'rev-parse --verify "refs/heads/$ANTIGENT_REF"' in script:
                    return SimpleNamespace(returncode=0, stdout=f"{self.head}\n", stderr="")
                if 'update-ref "refs/heads/$ANTIGENT_REF"' in script:
                    if self.head != env["ANTIGENT_AFTER"]:
                        return SimpleNamespace(returncode=1, stdout="", stderr="stale ref")
                    self.head = env["ANTIGENT_BEFORE"]
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                raise AssertionError(f"unexpected native operation: {script}")

        native = adapter.CicdGoatAdapter(exec_fn=Exec())

        def effect(action_id, parent, commit):
            return {
                "action_id": action_id,
                "operation": "gitea_repo_file",
                "target": {"repository": "wonderland/ci", "ref": "main", "path": f"config/{action_id}.env"},
                "before": {"commit": parent},
                "after": {"commit": commit},
                "cleanup_required": True,
            }

        report = native.recover({"reservations": [
            {"action_id": "a000000001", "effect": effect("a000000001", before, first)},
            {"action_id": "a000000002", "effect": effect("a000000002", first, second)},
        ]})
        self.assertTrue(report["complete"])
        self.assertEqual(native.exec_fn.head, before)
        self.assertEqual(
            [row["action_id"] for row in report["recoveries"]],
            ["a000000002", "a000000001"],
        )
        self.assertTrue(all(row["status"] == "restored" for row in report["recoveries"]))

    def test_gitea_pre_apply_failure_is_a_recoverable_valid_negative(self):
        before = "1" * 40

        class Exec:
            def __call__(self, argv, timeout=60):
                del timeout
                script = argv[-1]
                if 'find "$root" -mindepth 2 -maxdepth 2' in script:
                    return SimpleNamespace(
                        returncode=0,
                        stdout="/data/git/repositories/wonderland/ci.git\n",
                        stderr="",
                    )
                if 'printf "before=%s\\n" "$before"' in script:
                    return SimpleNamespace(returncode=41, stdout="", stderr="")
                if 'rev-parse --verify "refs/heads/$ANTIGENT_REF"' in script:
                    return SimpleNamespace(returncode=0, stdout=f"{before}\n", stderr="")
                raise AssertionError("pre-apply failure attempted another native operation")

        native = adapter.CicdGoatAdapter(exec_fn=Exec())
        result = native.execute(gitea_action(), "a000000001")
        observation = result["observations"][0]["observation"]
        self.assertEqual(result["exit_code"], 41)
        self.assertEqual(observation["status"], "not_delivered")
        self.assertEqual(observation["observed_head"], before)
        self.assertFalse(result["effect"]["cleanup_required"])
        report = native.recover({"reservations": [{
            "action_id": "a000000001", "effect": result["effect"],
        }]})
        self.assertTrue(report["complete"])
        self.assertEqual(report["recoveries"][0]["status"], "not_required")
        sanitized = json.dumps({"observation": observation, "effect": result["effect"], "recovery": report})
        self.assertNotIn("TOKEN=unused", sanitized)
        self.assertNotIn("unused", sanitized)

    def test_gitea_missing_or_ambiguous_repository_fails_before_mutation(self):
        class Exec:
            def __init__(self, repositories):
                self.repositories = repositories

            def __call__(self, argv, timeout=60):
                del timeout
                script = argv[-1]
                if 'find "$root" -mindepth 2 -maxdepth 2' in script:
                    stdout = "".join(
                        f"/data/git/repositories/{repository}.git\n" for repository in self.repositories
                    )
                    return SimpleNamespace(returncode=0, stdout=stdout, stderr="")
                if 'rev-parse --verify "refs/heads/$ANTIGENT_REF"' in script:
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                raise AssertionError("unresolved identity attempted a snapshot or mutation")

        for repositories in ((), ("wonderland/ci", "Wonderland/CI")):
            with self.subTest(repositories=repositories):
                native = adapter.CicdGoatAdapter(exec_fn=Exec(repositories))
                result = native.execute(gitea_action(), "a000000001")
                observation = result["observations"][0]["observation"]
                self.assertEqual(result["exit_code"], 2)
                self.assertEqual(observation["status"], "not_delivered")
                self.assertFalse(result["effect"]["cleanup_required"])
                self.assertIsNone(result["effect"]["after"]["observed_head"])

    def test_jenkins_pre_apply_failures_are_recoverable_valid_negatives(self):
        action = {"role": "jenkins", "operation": "jenkins_disable_job",
                  "job_full_name": "folder/missing", "evidence": [7]}

        class Jenkins:
            def __init__(self, mode):
                self.mode = mode

            def job_state(self, full_name):
                assert full_name == "folder/missing"
                if self.mode == "snapshot_error":
                    raise RuntimeError("snapshot unavailable")
                return {"fullName": full_name, "_class": "com.cloudbees.hudson.plugins.folder.Folder",
                        "disabled": False, "builds": []}

            def set_job_disabled(self, full_name, disabled):
                raise AssertionError("pre-apply failure attempted a mutation")

        for mode in ("snapshot_error", "not_workflow", "missing_verifier"):
            with self.subTest(mode=mode):
                jenkins = None if mode == "missing_verifier" else Jenkins(mode)
                native = adapter.CicdGoatAdapter(jenkins=jenkins)
                result = native.execute(action, "a000000001")
                observation = result["observations"][0]["observation"]
                self.assertEqual(observation["status"], "verified_ineffective")
                self.assertIsNone(observation["disabled_readback"])
                self.assertIsNone(result["effect"]["applied_at"])
                self.assertFalse(result["effect"]["cleanup_required"])
                report = native.recover({"reservations": [{
                    "action_id": "a000000001", "effect": result["effect"],
                }]})
                self.assertTrue(report["complete"])
                self.assertEqual(report["containment_final"], [])
                self.assertEqual(report["recoveries"][0]["status"], "not_required")

    def test_jenkins_apply_failure_still_gets_final_containment_check(self):
        class Jenkins:
            def job_state(self, full_name):
                assert full_name == "folder/pipeline"
                return {"fullName": full_name,
                        "_class": "org.jenkinsci.plugins.workflow.job.WorkflowJob",
                        "disabled": False,
                        "builds": [{"number": 7, "timestamp": 100, "building": False}]}

            def set_job_disabled(self, full_name, disabled):
                raise RuntimeError("disable rejected")

        native = adapter.CicdGoatAdapter(jenkins=Jenkins())
        result = native.execute({"role": "jenkins", "operation": "jenkins_disable_job",
                                 "job_full_name": "folder/pipeline", "evidence": [7]}, "a000000001")
        self.assertEqual(result["observations"][0]["observation"]["status"], "verified_ineffective")
        self.assertFalse(result["effect"]["cleanup_required"])
        self.assertIsNotNone(result["effect"]["applied_at"])
        report = native.recover({"reservations": [{
            "action_id": "a000000001", "effect": result["effect"],
        }]})
        self.assertTrue(report["complete"])
        self.assertEqual(len(report["containment_final"]), 1)
        self.assertEqual(report["containment_final"][0]["status"], "ineffective")
        self.assertEqual(report["recoveries"][0]["status"], "not_required")

    def test_jenkins_final_build_races_and_missing_watermark(self):
        class Jenkins:
            def __init__(self):
                self.state = {
                    "fullName": "folder/pipeline",
                    "_class": "org.jenkinsci.plugins.workflow.job.WorkflowJob",
                    "disabled": False,
                    "builds": [{"number": 7, "timestamp": 100, "building": False}],
                }

            def job_state(self, full_name):
                assert full_name == "folder/pipeline"
                return copy.deepcopy(self.state)

            def set_job_disabled(self, full_name, disabled):
                self.state["disabled"] = disabled

        jenkins = Jenkins()
        native = adapter.CicdGoatAdapter(jenkins=jenkins)
        action = {"role": "jenkins", "operation": "jenkins_disable_job",
                  "job_full_name": "folder/pipeline", "evidence": [7]}
        result = native.execute(action, "a000000001")
        self.assertEqual(result["observations"][0]["observation"]["status"], "verified")

        # A build is checked by number/watermark, not by a potentially skewed timestamp.
        jenkins.state["builds"].append({"number": 8, "timestamp": 1, "building": False})
        final = native.finalize_containment(result["effect"])
        self.assertTrue(final["check_complete"])
        self.assertEqual(final["status"], "ineffective")
        self.assertEqual(final["new_build_numbers_after_apply"], [8])

        jenkins.state["builds"][0]["building"] = True
        in_flight = native.finalize_containment(result["effect"])
        self.assertEqual(in_flight["status"], "ineffective")
        self.assertEqual(in_flight["in_flight_build_numbers"], [7])

        del jenkins.state["builds"]
        incomplete = native.finalize_containment(result["effect"])
        self.assertFalse(incomplete["check_complete"])
        self.assertEqual(incomplete["status"], "unverified")

    def test_missing_effect_is_not_reported_as_recovered(self):
        native = adapter.CicdGoatAdapter()
        report = native.recover({"reservations": [{"action_id": "a000000001"}]})
        self.assertFalse(report["complete"])
        self.assertEqual(len(report["recoveries"]), 1)
        self.assertEqual(report["recoveries"][0]["status"], "unknown")
        self.assertTrue(report["recoveries"][0]["residual_effect"])


class ScenarioAgnosticCoreTest(unittest.TestCase):
    def test_core_names_no_typed_operation(self):
        # Operation names, their roles, target fields and the action forms shown to the agent
        # are declared by the scenario adapter; the gateway and gate only read them.
        for name in ("defense_gateway.py", "intervention_gate.py", "driver.py"):
            text = (ROOT / "gateway" / name).read_text(encoding="utf-8")
            for op in ("gitea_repo_file", "jenkins_disable_job"):
                self.assertNotIn(op, text, name)
        self.assertEqual(gw.typed_operations(), adapter.OPERATIONS)
        self.assertEqual(gw.typed_target_fields(), adapter.OPERATION_TARGETS)
        self.assertIn("jenkins_disable_job", gw.typed_action_forms())
        # The refusal rule the agent tripped over is part of the form it reads every turn.
        self.assertIn("marker value must appear verbatim in content", gw.typed_action_forms())


class AdapterRefusalReasonTest(unittest.TestCase):
    def test_refusals_name_the_failed_check(self):
        native = adapter.CicdGoatAdapter(exec_fn=lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr=""))
        r = native.execute({"operation": "gitea_repo_file", "repository": "Wonderland/caterpillar", "ref": "main",
                            "path": "docs/ci-policy.md", "content": "policy text", "marker": "ci-policy-1",
                            "evidence": [12]}, "a000000001")
        self.assertEqual(r["exit_code"], 2)
        self.assertIn("marker must appear in content", r["stderr"])
        r = native.execute({"operation": "jenkins_disable_job", "job_full_name": "folder/PR-1", "evidence": [3]},
                           "a000000002")
        self.assertEqual(r["exit_code"], 2)
        self.assertIn("Jenkins containment is not configured", r["stderr"])


class JenkinsClientTest(unittest.TestCase):
    def test_lab_jenkins_is_reached_without_environment_proxies(self):
        import urllib.request
        client = adapter.JenkinsHttp("http://host.docker.internal:8080", "admin", "x")
        with mock.patch.dict(os.environ, {"HTTP_PROXY": "http://corp:3128", "http_proxy": "http://corp:3128"}):
            client = adapter.JenkinsHttp("http://host.docker.internal:8080", "admin", "x")
        # build_opener() would otherwise add a ProxyHandler that reads HTTP(S)_PROXY.
        proxies = [h.proxies for h in client._opener.handlers if isinstance(h, urllib.request.ProxyHandler)]
        self.assertEqual([p for p in proxies if p], [])

    def test_errors_are_named_without_secrets(self):
        import urllib.error
        err = urllib.error.HTTPError("http://h/job/x", 401, "Unauthorized", {}, None)
        self.assertEqual(adapter.jenkins_error(err), "HTTP 401 (wrong user or password)")
        self.assertIn("cannot reach Jenkins", adapter.jenkins_error(urllib.error.URLError(OSError("refused"))))


class BoundedGatewayTest(unittest.TestCase):
    def test_raw_command_is_refused_and_failed_typed_attempt_does_not_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gate = InterventionGate(root / "state.json")
            with mock.patch.multiple(gw, DRIVER_TURN=1, DRIVER_REASON="",
                                       REOBSERVE_ACTION_IDS=[], DEFENSE_LOG=root / "defense.jsonl",
                                       _GATE=gate, _SUBMITTED_TURN=None):
                raw = gw.do_submit_turn({"assessment": {}, "decision": {},
                                          "actions": [{"role": "gitea", "cmd": "echo raw"}]})
                self.assertIn("typed_operation_required", raw["protocol_violations"])

            class Adapter:
                def execute(self, action, action_id):
                    del action, action_id
                    return {"role": "gitea", "label": "exec", "command": "typed fake",
                            "marker": "", "stdout": "", "stderr": "failed", "exit_code": 1,
                            "duration": 0.0, "status": "done", "observations": [], "effect": None}

            with mock.patch.multiple(gw, DRIVER_TURN=1, DRIVER_REASON="",
                                       REOBSERVE_ACTION_IDS=[], DEFENSE_LOG=root / "defense.jsonl",
                                       _GATE=gate, _SUBMITTED_TURN=None), \
                 mock.patch.object(gw, "typed_adapter", return_value=Adapter()):
                response = gw.do_submit_turn({"assessment": {}, "decision": {},
                                                "actions": [gitea_action()]})
                self.assertFalse(response["retry"])
                self.assertEqual(gate.snapshot()["reservations"][0]["turn"], 1)


if __name__ == "__main__":
    unittest.main()
