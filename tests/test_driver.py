"""v0.14/v0.15 event-driven driver, recon signals and metrics (no Docker, no OpenCode).

  python -m unittest discover -s tests -v
"""
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "gateway"))
sys.path.insert(0, str(ROOT / "eval"))
import os  # noqa: E402
os.environ.setdefault("ANTIGENT_SCENARIO", str(ROOT / "scenarios" / "cicd-goat"))
import defense_gateway as gw  # noqa: E402
import driver  # noqa: E402
import metrics  # noqa: E402


def ev(i, ts, kind="auth-burst", level="elevated"):
    return {"index": i, "ts": ts, "kind": kind, "level": level, "source": "gitea", "summary": "x"}


def write_context_fixture(root, reservation_count=1):
    events = [
        {"index": 1, "ts": 100.0, "kind": "access-log", "level": "raw", "source": "gitea",
         "client": "172.19.0.1", "method": "GET",
         "path": "/Wonderland/caterpillar.git/info/refs?service=git-upload-pack&token=QUERYSECRET",
         "summary": "RAWSESSIONSECRET"},
        {"index": 2, "ts": 101.0, "kind": "access-log", "level": "raw", "source": "gitea",
         "internal": True, "method": "GET", "path": "/internal-scan", "summary": "INTERNALSECRET"},
        {"index": 3, "ts": 102.0, "kind": "net-http", "level": "raw", "source": "jenkins",
         "client": "172.19.0.1", "method": "GET",
         "path": "/job/Wonderland/job/caterpillar-prod/api/json?token=QUERYSECRET",
         "summary": "credential=RAWSESSIONSECRET"},
    ]
    (root / "sensor.jsonl").write_text("".join(
        json.dumps({"type": "observed", "event": event}) + "\n" for event in events
    ), encoding="utf-8")
    reservations, defense = [], []
    for index in range(reservation_count):
        action_id = f"{index + 1:010x}"
        evidence = f"{index + 1:064x}"
        reservations.append({
            "action_id": action_id, "turn": index + 1, "operation": "gitea_repo_file",
            "execution_exit_code": 128, "reobserved_at": 200.0 + index,
            "final_reobserved_at": None, "observation_ids": [evidence],
            "effect": {"target": {"repository": "Wonderland/caterpillar", "ref": "main",
                                  "path": f"deploy/file-{index}.json"},
                       "content": "DECOYCONTENTSECRET", "marker": "MARKERSECRET"},
        })
        defense.append({"type": "action_observation", "action_id": action_id,
                        "observation": {"status": "not_delivered", "evidence_id": evidence,
                                        "raw": "RAWRECEIPTSECRET"}})
    defense.append({"type": "record", "record": {"kind": "assessment", "intent": "RAWMODELSECRET"}})
    (root / "defense.jsonl").write_text("".join(json.dumps(row) + "\n" for row in defense), encoding="utf-8")
    (root / "intervention_state.json").write_text(json.dumps({
        "schema_version": "intervention_state_v1", "protocol_id": "context_managed_multi_turn_v1",
        "max_interventions": None, "reservations": reservations,
    }), encoding="utf-8")


class DriverTest(unittest.TestCase):
    def test_debounce_and_max_wait(self):
        p = driver.Pending()
        self.assertFalse(driver.should_fire(p, 100, None, False, 3, 15, 10))      # nothing pending
        p.add(ev(1, 100), 100)
        self.assertFalse(driver.should_fire(p, 101, None, False, 3, 15, 10))      # still bursting
        self.assertTrue(driver.should_fire(p, 103, None, False, 3, 15, 10))       # quiet for 3 s
        for t in range(101, 116):                                                  # never quiet ...
            p.add(ev(t, t), t)
        self.assertTrue(driver.should_fire(p, 115, None, False, 3, 15, 10))       # ... max_wait hit

    def test_pause_and_cooldown(self):
        p = driver.Pending()
        p.add(ev(1, 100), 100)
        self.assertFalse(driver.should_fire(p, 110, None, True, 3, 15, 10))       # paused
        self.assertFalse(driver.should_fire(p, 110, 105, False, 3, 15, 10))       # cooldown after a turn
        self.assertTrue(driver.should_fire(p, 116, 105, False, 3, 15, 10))

    def test_activity_tier(self):
        p = driver.Pending()
        p.add_raw(ev(1, 100, "access-log", "raw"), 100)
        self.assertIsNone(driver.should_fire(p, 110, None, False, 3, 15, 10, 20))            # < 20 s of activity
        self.assertEqual(driver.should_fire(p, 120, None, False, 3, 15, 10, 20), "activity")
        self.assertIsNone(driver.should_fire(p, 120, None, False, 3, 15, 10, 0))             # tier disabled
        p.add(ev(2, 119), 119)                                                                 # elevated arrives
        self.assertIsNone(driver.should_fire(p, 120, None, False, 3, 15, 10, 20))            # wait for its debounce
        self.assertEqual(driver.should_fire(p, 122, None, False, 3, 15, 10, 20), "elevated")
        q = driver.Pending()
        q.add_raw(ev(3, 200, "access-log", "raw"), 200)
        self.assertIsNone(driver.should_fire(q, 215, 205, False, 3, 15, 10, 20))             # 20 s counted from turn end
        self.assertEqual(driver.should_fire(q, 225, 205, False, 3, 15, 10, 20), "activity")

    def test_target_setup_over_loopback_never_triggers(self):
        # CI/CD Goat seeds Gitea from inside the container (::1 / 127.0.0.1): repos, hooks,
        # tokens. That is the target configuring itself, not a client to watch.
        out = []
        o = gw.Observer(sink=out.append)
        for i in range(12):
            o._new_source("gitea", f"router: completed POST /api/v1/admin/users{i} for [::1]:4{i:03d}, 201 Created", 1000 + i)
            o._new_source("gitea", f"router: completed GET /Wonderland/r{i}.git/info/refs for 127.0.0.1:5{i:03d}, 401 Unauthorized", 1000 + i)
        self.assertEqual([e for e in out if e["level"] == "elevated"], [])
        self.assertFalse(o.is_internal("10.0.0.5"))
        for addr in ("::1", "[::1]", "127.0.0.1", "127.8.9.10"):
            self.assertTrue(o.is_internal(addr), addr)

    def test_recon_and_error_burst(self):
        out = []
        o = gw.Observer(sink=out.append)
        for i in range(10):
            o._new_source("gitea", f"router: completed GET /repo{i}.git/info/refs for 10.0.0.5:4{i:03d}, 404 Not Found", 1000 + i)
        kinds = [e["kind"] for e in out]
        self.assertEqual(kinds.count("new-source"), 1)
        self.assertIn("error-burst", kinds)       # 5 x 404 within the window
        self.assertIn("recon-burst", kinds)       # 10 requests within the window
        eb = next(e for e in out if e["kind"] == "error-burst")
        self.assertEqual(eb["level"], "elevated")
        self.assertEqual(eb["ip"], "10.0.0.5")
        n = len(out)
        o._new_source("gitea", "router: completed GET /a for 10.0.0.5:1, 401 Unauthorized", 1011)
        self.assertEqual(len(out), n)              # 401 is auth, never an error-burst on its own

    def test_prompt_first_and_continued(self):
        p = driver.Pending()
        p.add(ev(7, 100, "new-source"), 100)
        p.add(ev(9, 101, "auth-burst"), 101)
        # opening turn: full prompt with the scenario brief
        first = driver.build_prompt(1, 6, 9, p, ["gitea", "prod"], first=True)
        self.assertIn("[Antigent driver turn T1]", first)
        self.assertIn("since_index=6", first)
        self.assertIn("auth-burst x1, new-source x1", first)
        self.assertIn("CONTINUOUS session", first)
        self.assertIn("--- Scenario ---", first)
        self.assertIn("Exec roles: gitea, prod", first)
        self.assertIn("submit_turn EXACTLY ONCE", first)
        # continued turn: short prompt, NO scenario block (the session already holds it)
        cont = driver.build_prompt(2, 9, 12, p, ["gitea", "prod"], first=False)
        self.assertIn("[Antigent driver turn T2]", cont)
        self.assertNotIn("--- Scenario ---", cont)
        self.assertIn("submit_turn EXACTLY ONCE", cont)
        self.assertLess(len(cont), len(first))
        act = driver.Pending(); act.add_raw(ev(10, 300, "access-log", "raw"), 300)
        self.assertIn("1 raw events, no elevated ones", driver.build_prompt(3, 9, 10, act, ["gitea"], "activity", False))

    def test_prompt_forbids_in_turn_retry(self):
        p = driver.Pending()
        p.add(ev(7, 100), 100)
        first = driver.build_prompt(1, 6, 7, p, ["gitea"], first=True)
        self.assertIn("NO in-turn retry", first)
        self.assertIn("The driver records the reobservation of every mutating attempt itself", first)
        later = driver.build_prompt(2, 6, 7, p, ["gitea"], first=False)
        self.assertIn("No in-turn retry", later)
        self.assertNotIn("retry=true", later)

    def test_later_turns_repeat_only_a_short_reminder(self):
        # The full cycle is given once; AGENTS.md (system prompt) carries the rules, so later
        # turns stay short and the session grows slowly (lower time to first token).
        p = driver.Pending()
        p.add(ev(7, 100), 100)
        first = driver.build_prompt(1, 6, 7, p, ["gitea"], first=True)
        later = driver.build_prompt(2, 6, 7, p, ["gitea"], first=False)
        self.assertLess(len(later), len(first) // 3)
        self.assertIn("EXACTLY ONCE", later)
        self.assertIn("actions=[]", later)
        self.assertIn("since_index=6", later)
        self.assertIn("--- New events ---", later)
        self.assertNotIn("Select exactly one strategy Skill", later)
        # After a briefing-only opening (T0), the first action turn still gets the full cycle once.
        after_briefing = driver.build_prompt(1, 6, 7, p, ["gitea"], first=False, full_cycle=True)
        self.assertIn("Select exactly one strategy Skill", after_briefing)
        self.assertNotIn("--- Scenario ---", after_briefing)

    def test_reobservation_prompt_is_read_only(self):
        txt = driver.build_reobservation_prompt(4, 10, 14, ["gitea"])
        self.assertIn("since_index=10", txt)
        self.assertIn("empty result is valid", txt)
        self.assertIn('decision.strategy="no_intervention"', txt)
        self.assertIn("actions=[]", txt)
        self.assertIn("read-only", txt)

    def test_bounded_turn_retries_only_missing_submission(self):
        results = [
            {"exit_code": 0, "submitted": False, "intervened": False},
            {"exit_code": 0, "submitted": True, "intervened": False},
        ]
        with mock.patch.object(driver, "TURN_RETRIES", 1), \
             mock.patch.object(driver, "emit"), \
             mock.patch.object(driver, "run_turn", side_effect=results) as run:
            result = driver.run_bounded_turn(2, 0, 1, driver.Pending())
        self.assertTrue(driver.turn_succeeded(result))
        self.assertEqual(run.call_count, 2)

    def test_bounded_turn_does_not_repeat_accepted_action_after_cli_error(self):
        accepted_error = {"exit_code": 1, "submitted": True, "intervened": True}
        with mock.patch.object(driver, "TURN_RETRIES", 3), \
             mock.patch.object(driver, "emit"), \
             mock.patch.object(driver, "run_turn", return_value=accepted_error) as run:
            result = driver.run_bounded_turn(2, 0, 1, driver.Pending())
        self.assertFalse(driver.turn_succeeded(result))
        self.assertEqual(run.call_count, 1)

    def test_run_turn_requires_gateway_acceptance(self):
        import tempfile
        out = Path(tempfile.mkdtemp())
        defense = out / "defense.jsonl"

        def fake_run(*args, **kwargs):
            defense.write_text(json.dumps({"type": "turn_accepted", "turn": 2,
                                           "intervened": True,
                                           "delivered_action_ids": ["a1"]}) + "\n")
            return 0, "", "", False

        with mock.patch.object(driver, "DEFENSE", defense), \
             mock.patch.object(driver, "TURN_DIR", out / "turns"), \
             mock.patch.object(driver, "emit"), \
             mock.patch.object(driver, "run_opencode", side_effect=fake_run):
            result = driver.run_turn(2, 0, 1, driver.Pending())
        self.assertTrue(result["submitted"])
        self.assertTrue(result["intervened"])
        self.assertEqual(result["delivered_action_ids"], ["a1"])

    def test_turn_stops_once_the_submission_is_accepted(self):
        # The closing model message after submit_turn is not waited for: a process that would
        # run 30 s is stopped about EARLY_EXIT_GRACE after the gateway accepted the turn.
        import sys as _sys
        import tempfile
        out = Path(tempfile.mkdtemp())
        defense = out / "defense.jsonl"
        defense.write_text("")
        script = ("import json,time,sys; time.sleep(0.3); "
                  f"open({str(defense)!r},'a').write(json.dumps({{'type':'turn_accepted','turn':5}})+'\\n'); "
                  "print('submitted', flush=True); time.sleep(30)")
        with mock.patch.object(driver, "DEFENSE", defense), mock.patch.object(driver, "EARLY_EXIT_GRACE", 0.2):
            t0 = time.time()
            code, stdout, _err, early = driver.run_opencode([_sys.executable, "-c", script], dict(os.environ), 20, 5, 0)
        self.assertTrue(early)
        self.assertEqual(code, 0)
        self.assertIn("submitted", stdout)
        self.assertLess(time.time() - t0, 8)
        # another turn's acceptance does not stop this one; the timeout still applies
        with mock.patch.object(driver, "DEFENSE", defense):
            code, _o, _e, early = driver.run_opencode([_sys.executable, "-c", "import time; time.sleep(30)"],
                                                       dict(os.environ), 1.0, 6, defense.stat().st_size)
        self.assertEqual((code, early), (124, False))

    def test_reobservation_is_linked_without_a_model_turn(self):
        import tempfile
        from intervention_gate import InterventionGate
        out = Path(tempfile.mkdtemp())
        defense = out / "defense.jsonl"
        gate = InterventionGate(out / "intervention_state.json", defense_log=defense,
                                target_fields={"op": ("t",)})
        gate.initialize()
        r = gate.reserve({"operation": "op", "t": "x"}, "a1", 3)
        self.assertTrue(r["allowed"])
        self.assertEqual(gate.reserve({"operation": "op", "t": "y"}, "a2", 4)["reason"], "reobservation_pending")
        events = []
        with mock.patch.object(driver, "DEFENSE", defense), mock.patch.object(driver, "emit", events.append):
            driver.reobserve_deterministic(["a1"], 3, 10, 20)
        self.assertTrue(gate.reserve({"operation": "op", "t": "y"}, "a2", 4)["allowed"])   # next action allowed
        self.assertEqual(events[0]["type"], "reobservation")
        self.assertEqual(events[0]["mode"], "deterministic")

    def test_exit_zero_without_submit_is_failure(self):
        self.assertFalse(driver.turn_succeeded({"exit_code": 0, "submitted": False}))
        self.assertFalse(driver.turn_succeeded({"exit_code": 1, "submitted": True}))
        self.assertTrue(driver.turn_succeeded({"exit_code": 0, "submitted": True}))

    def test_events_inlined_in_prompt(self):
        # v0.16.7: the driver hands the new (external, non-baseline) events to the agent in the
        # prompt, so it can skip the observe_events round trip. Internal/baseline are not inlined.
        p = driver.Pending()
        e1 = ev(7, 100, "new-source"); e1["client"] = "172.19.0.1"
        p.add(e1, 100)
        e2 = ev(8, 101, "access-log", "raw"); e2["client"] = "172.19.0.1"; e2["summary"] = "GET /api/v1/repos/search 200"
        p.add_raw(e2, 101)
        e3 = ev(9, 102, "access-log", "raw"); e3["internal"] = True; e3["summary"] = "CI scan"
        p.add_raw(e3, 102)
        txt = driver.build_prompt(2, 6, 9, p, ["gitea"], first=False)
        self.assertIn("--- New events ---", txt)
        self.assertIn("#7 elevated new-source on gitea from 172.19.0.1", txt)
        self.assertIn("GET /api/v1/repos/search 200", txt)
        self.assertNotIn("CI scan", txt)
        self.assertIn("only if something you need is not listed", txt)

    def test_context_managed_digest_preserves_exact_history_without_raw_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_context_fixture(root)
            with mock.patch.multiple(driver, SENSOR=root / "sensor.jsonl", DEFENSE=root / "defense.jsonl",
                                     OUT_DIR=root, PROTOCOL_ID="context_managed_multi_turn_v1",
                                     CONTEXT_CHAR_LIMIT=16000):
                digest = driver.build_context_digest(3)
                self.assertIn("PAST observations only", digest)
                self.assertIn("/Wonderland/caterpillar.git/info/refs ", digest)
                self.assertIn("repository=Wonderland/caterpillar ref=main path=deploy/file-0.json", digest)
                self.assertIn("native=not_delivered exit=128 linked=yes final=no", digest)
                self.assertIn("evidence=" + f"{1:064x}", digest)
                self.assertIn("predicted_next[0]", digest)
                self.assertIn("future read certainty is not required", digest)
                self.assertIn("only from post-delivery attacker observations", digest)
                self.assertNotIn("QUERYSECRET", digest)
                self.assertNotIn("RAWSESSIONSECRET", digest)
                self.assertNotIn("INTERNALSECRET", digest)
                self.assertNotIn("DECOYCONTENTSECRET", digest)
                self.assertNotIn("MARKERSECRET", digest)
                self.assertNotIn("RAWRECEIPTSECRET", digest)
                self.assertNotIn("RAWMODELSECRET", digest)
                self.assertNotIn("/internal-scan", digest)
                pending = driver.Pending()
                prompt = driver.build_prompt(2, 3, 3, pending, ["gitea"], first=True)
                self.assertIn(digest, prompt)
                self.assertIn("no fixed numeric intervention limit", prompt)
                reobservation = driver.build_reobservation_prompt(3, 3, 3, ["gitea"])
                self.assertIn(digest, reobservation)
                self.assertIn("read-only", reobservation)

    def test_context_managed_digest_is_bounded_and_fails_to_no_action(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_context_fixture(root, reservation_count=12)
            with mock.patch.multiple(driver, SENSOR=root / "sensor.jsonl", DEFENSE=root / "defense.jsonl",
                                     OUT_DIR=root, PROTOCOL_ID="context_managed_multi_turn_v1",
                                     CONTEXT_SURFACE_LIMIT=48,
                                     CONTEXT_CHAR_LIMIT=1800):
                digest = driver.build_context_digest(3)
                self.assertLessEqual(len(digest), 1800)
                self.assertIn("older receipts omitted", digest)
                self.assertIn("intervention history is incomplete", digest)
                self.assertIn("choose no_intervention", digest)
                self.assertNotIn("DECOYCONTENTSECRET", digest)

    def test_context_managed_digest_malformed_or_unverified_history_fails_closed(self):
        cases = ("malformed_state", "unverified_native", "malformed_action_id", "malformed_observation_ids")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                write_context_fixture(root)
                if case == "malformed_state":
                    (root / "intervention_state.json").write_text("[]\n", encoding="utf-8")
                    (root / "sensor.jsonl").write_text(
                        "[]\nnot-json\n" + (root / "sensor.jsonl").read_text(encoding="utf-8"),
                        encoding="utf-8",
                    )
                    (root / "defense.jsonl").write_text(
                        "[]\nnot-json\n" + (root / "defense.jsonl").read_text(encoding="utf-8"),
                        encoding="utf-8",
                    )
                elif case == "unverified_native":
                    rows = [json.loads(line) for line in
                            (root / "defense.jsonl").read_text(encoding="utf-8").splitlines()]
                    rows[0]["observation"]["status"] = "unverified"
                    (root / "defense.jsonl").write_text(
                        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8",
                    )
                else:
                    state_path = root / "intervention_state.json"
                    state = json.loads(state_path.read_text(encoding="utf-8"))
                    if case == "malformed_action_id":
                        state["reservations"][0]["action_id"] = ["unhashable"]
                    else:
                        state["reservations"][0]["observation_ids"] = {"not": "a list"}
                    state_path.write_text(json.dumps(state), encoding="utf-8")
                with mock.patch.multiple(driver, SENSOR=root / "sensor.jsonl",
                                         DEFENSE=root / "defense.jsonl", OUT_DIR=root,
                                         PROTOCOL_ID="context_managed_multi_turn_v1",
                                         CONTEXT_CHAR_LIMIT=16000):
                    digest = driver.build_context_digest(3)
                    self.assertIn("Context is incomplete or reobservation is pending", digest)
                    self.assertIn("choose no_intervention", digest)
                    if case == "unverified_native":
                        self.assertIn("native=unverified", digest)
                    if case == "malformed_action_id":
                        self.assertIn("unknown gitea_repo_file", digest)

    def test_context_surface_history_preserves_noncontiguous_indexes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_context_fixture(root)
            repeated = {
                "index": 5, "ts": 105.0, "kind": "access-log", "level": "raw", "source": "gitea",
                "client": "172.19.0.1", "method": "GET",
                "path": "/Wonderland/caterpillar.git/info/refs?service=git-upload-pack",
                "summary": "safe repeated surface",
            }
            with (root / "sensor.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"type": "observed", "event": repeated}) + "\n")
            with mock.patch.object(driver, "SENSOR", root / "sensor.jsonl"):
                surfaces, _ = driver._surface_history(5)
            caterpillar = next(line for line in surfaces if "caterpillar.git" in line)
            self.assertTrue(caterpillar.startswith("#1,#5 "), caterpillar)
            self.assertNotIn("#1..#5", caterpillar)

    def test_policy_and_skills_use_domain_neutral_terms(self):
        # The policy is meant to carry over to other environments: CI/CD vocabulary (and any other
        # domain's) belongs in the scenario adapter, not in AGENTS.md, the skills or the driver prompt.
        import re
        banned = re.compile(r"(?i)\b(repositor\w*|repos?|refs?|fork\w*|branch\w*|pipelines?|jobs?|commit\w*|clone\w*|"
                            r"jenkins\w*|gitea|gitlab|pull request)\b")
        files = [ROOT / "AGENTS.md"] + sorted((ROOT / ".opencode" / "skills").glob("*/SKILL.md"))
        for f in files:
            self.assertEqual(banned.findall(f.read_text(encoding="utf-8")), [], f.name if f.name != "SKILL.md" else f.parent.name)
        p = driver.Pending()
        p.add({"index": 1, "kind": "new-source", "source": "x", "level": "elevated", "summary": "s"}, 1.0)
        from unittest import mock
        with mock.patch.object(driver, "scenario_brief", return_value=""), \
                mock.patch.object(driver, "typed_action_forms", return_value="", create=True):
            prompt = driver.build_prompt(1, 0, 1, p, ["x"], "elevated", first=True, full_cycle=True)
        self.assertEqual(banned.findall(prompt), [])   # the driver's own wording (adapter text excluded)

    def test_strategy_skills_are_split_and_capability_gated(self):
        skills = ROOT / ".opencode" / "skills"
        common = (skills / "deception-honeytoken" / "SKILL.md").read_text(encoding="utf-8")
        artifact = (skills / "artifact-path-decoy" / "SKILL.md").read_text(encoding="utf-8")
        instruction = (skills / "in-environment-instruction" / "SKILL.md").read_text(encoding="utf-8")
        containment = (skills / "containment" / "SKILL.md").read_text(encoding="utf-8")
        context = (ROOT / "scenarios" / "cicd-goat" / "context.md").read_text(encoding="utf-8")
        policy = (ROOT / "AGENTS.md").read_text(encoding="utf-8")

        self.assertIn("not as a third ambiguous strategy", common)
        self.assertIn("new-file variant", artifact)
        self.assertIn("does not edit an existing artifact", artifact)
        self.assertIn("Do not mix imperative instructions", artifact)
        self.assertIn("Do not mix factual credential/configuration decoys", instruction)
        self.assertIn("Never request destructive actions", instruction)
        self.assertIn("non-secret `marker`", instruction)
        self.assertIn("not the full graduated S5", containment)
        self.assertIn("planted decoy's marker being read or followed", containment)
        self.assertIn("attacker-owned", common)
        for text in (common, artifact, instruction):
            self.assertIn("Future read certainty is not required", text)
            self.assertIn("marker", text)

        self.assertIn("`artifact-path-decoy` (S1)", context)
        self.assertIn("`in-environment-instruction` (S3)", context)
        self.assertIn("S2 `response-diversion` remains pending", context)
        self.assertIn("S4 `honeypot-diversion`", context)
        self.assertIn("future read certainty is not required", context)
        self.assertIn("not attacker read/follow or defense success", context)
        self.assertIn("previously unused relative `path`", context)
        self.assertIn("do not claim that this new path was observed", context)
        self.assertIn("`decision.preempts` is 1-based", context)
        self.assertNotIn("If no concrete post-apply attacker read/access path", context)
        self.assertIn("Use exactly one scenario-supported strategy per action", policy)
        self.assertIn("deception-honeytoken` is only their common rule set", policy)
        self.assertIn("attacker-owned copy", policy)
        self.assertIn("at its top level, or in a directory", policy)          # placement for discovery
        self.assertIn("Placement for discovery", artifact)
        self.assertIn("planted decoy is also a tripwire", policy)
        self.assertIn("has not produced containment-eligible read/follow evidence", policy)

    def test_context_managed_prompt_names_distinct_supported_strategies(self):
        p = driver.Pending()
        p.add(ev(7, 100), 100)
        with mock.patch.multiple(driver, PROTOCOL_ID="context_managed_multi_turn_v1",
                                 ):
            prompt = driver.build_prompt(2, 6, 7, p, ["gitea"], first=True)
        self.assertIn("exactly one strategy Skill", prompt)
        self.assertIn("artifact-path-decoy (factual)", prompt)
        self.assertIn("in-environment-instruction (bounded instruction)", prompt)
        self.assertIn("deception-honeytoken is only their common rule set", prompt)
        self.assertIn("Never infer an unadvertised adapter capability", prompt)
        self.assertIn("do not require guaranteed future read", prompt)
        self.assertIn("predicted_next[0] = 1; 0 = reactive only", prompt)
        self.assertIn("three active decoys per role", prompt)
        self.assertIn("attacker-owned working copy", prompt)
        self.assertIn("secrets-named directory", prompt)
        self.assertIn("decoy marker read/follow is confirmed", prompt)
        self.assertNotIn("one decoy per role", prompt)

    def test_parse_opencode_json(self):
        # v0.16.7: per-turn profile from `opencode run --format json`.
        lines = [
            {"type": "step_start", "timestamp": 1000, "part": {}},
            {"type": "tool_use", "timestamp": 1500, "part": {"tool": "antigent_submit_turn",
             "state": {"status": "completed", "input": {"a": 1}, "time": {"start": 1100, "end": 1400}}}},
            {"type": "step_finish", "timestamp": 3000, "part": {"tokens": {"input": 900, "output": 120,
             "reasoning": 300, "cache": {"read": 500}}}},
            {"type": "step_start", "timestamp": 3100, "part": {}},
            {"type": "text", "timestamp": 3200, "part": {"text": "done"}},
            {"type": "step_finish", "timestamp": 4100, "part": {"tokens": {"input": 1000, "output": 5}}},
            "not json",
        ]
        out = "\n".join(l if isinstance(l, str) else __import__("json").dumps(l) for l in lines)
        prof, text = driver.parse_opencode_json(out)
        self.assertEqual(prof["steps"], 2)
        self.assertEqual(prof["step_secs"], [2.0, 1.0])
        self.assertEqual(prof["tools"][0]["tool"], "antigent_submit_turn")
        self.assertEqual(prof["tools"][0]["secs"], 0.3)
        self.assertEqual(prof["tokens"], {"input": 1900, "output": 125, "reasoning": 300, "cache_read": 500})
        self.assertIn("done", text)
        # Wall time outside the event span (process start, teardown) is split out.
        driver.split_turn_time(prof, t0=0.4, t_end=7.1)
        self.assertEqual((prof["startup_secs"], prof["teardown_secs"]), (0.6, 3.0))
        self.assertNotIn("_first_ts", prof)

    def test_policy_does_not_let_an_old_decoy_cover_a_new_technique(self):
        policy = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        context = (ROOT / "scenarios" / "cicd-goat" / "context.md").read_text(encoding="utf-8")
        p = driver.Pending()
        prompt = driver.build_prompt(2, 0, 5, p, ["gitea", "jenkins"], "elevated", first=True)
        self.assertIn("the earlier decoy does not cover the new step", " ".join(policy.split()))
        self.assertIn("Being noticed by the attacker is not by itself a reason", " ".join(policy.split()))
        self.assertIn("at most 8 lines and 400 characters", policy)
        self.assertIn("not that such a job exists", context)
        self.assertIn("is not covered by an earlier decoy", prompt)

    def test_scenario_knowledge_is_configuration_not_answers(self):
        # The defender may know the defended environment, never the attack path, the
        # environment's weaknesses or what the attacker is expected to do.
        context = (ROOT / "scenarios" / "cicd-goat" / "context.md").read_text(encoding="utf-8")
        scenario = (ROOT / "scenarios" / "cicd-goat" / "scenario.json").read_text(encoding="utf-8")
        policy = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        for text in (context, scenario, policy):
            low = " ".join(text.lower().split())
            for phrase in ("attack path (", "typical attack", "leaked secrets", "secrets from history",
                           "mine secrets", "mining its history", "reportcov", "flag", "challenge",
                           "harvest ci secrets", "next: try"):
                self.assertNotIn(phrase, low, phrase)
        self.assertIn("contains no attack\npath", context)

    def test_policy_and_skills_name_no_scenario_at_all(self):
        # Everything about a particular environment (products, operations, paths) lives in
        # its Scenario Adapter folder; AGENTS.md and the skills stay scenario-agnostic.
        texts = {"AGENTS.md": (ROOT / "AGENTS.md").read_text(encoding="utf-8")}
        for f in (ROOT / ".opencode" / "skills").rglob("SKILL.md"):
            texts[str(f.relative_to(ROOT))] = f.read_text(encoding="utf-8")
        banned = ("jenkins", "gitea", "jenkinsfile", "workflowjob", "cicd", "goat", "wonderland",
                  "caterpillar", "repo_file", "disable_job", "ctfd")
        for name, text in texts.items():
            low = text.lower()
            self.assertEqual([b for b in banned if b in low], [], name)

    def test_rules_added_to_generic_policy_name_no_scenario(self):
        # AGENTS.md / skills / the driver's generic prompt stay scenario-agnostic; names of
        # products, operations and paths of one scenario belong in its context.md.
        added = [
            "A decoy covers only the predicted steps", "When tampering is in evidence",
            "Keep decoy `content` short", "Keep `content` short", "Once tampering is in evidence",
            "a pipeline file was changed (including",
        ]
        texts = [(ROOT / "AGENTS.md").read_text(encoding="utf-8")] + [
            f.read_text(encoding="utf-8") for f in (ROOT / ".opencode" / "skills").rglob("SKILL.md")]
        banned = ("jenkins", "gitea", "jenkinsfile", "workflowjob", "cicd", "wonderland", "caterpillar")
        for text in texts:
            for para in __import__("re").split(r"\n\s*(?:- |\d+\. )", text):
                if any(a in para for a in added):
                    low = para.lower()
                    self.assertFalse([b for b in banned if b in low], para)
        p = driver.Pending()
        prompt = driver.build_prompt(2, 0, 5, p, ["gitea", "jenkins"], "elevated", first=True)
        rule = prompt[prompt.index("A changed technique"):prompt.index("400 characters")]
        self.assertFalse([b for b in banned if b in rule.lower()], rule)

    def test_warmup_prompt_is_briefing_only(self):
        # v0.16.2: the T0 warmup primes the session with the scenario but forbids any action.
        w = driver.build_warmup_prompt(["gitea", "prod"])
        self.assertIn("briefing", w.lower())
        self.assertIn("--- Scenario ---", w)          # scenario is handed to the agent
        self.assertIn("Do NOT call any tools", w)     # no observe/submit at T0
        self.assertIn("CONTINUOUS session", w)
        self.assertIn("gitea, prod", w)
        self.assertNotIn("submit_turn EXACTLY ONCE", w)  # distinct from a real turn

    def test_metrics_v014_streams(self):
        events = [
            {"ts": 10, "type": "observed", "event": ev(1, 10, "access-log", "baseline")},
            {"ts": 100, "type": "observed", "event": ev(2, 100, "access-log", "raw")},
            {"ts": 101, "type": "observed", "event": ev(3, 101, "new-source", "elevated")},
            {"ts": 105, "type": "trigger", "turn": 1, "first_elevated_ts": 101},
            {"ts": 125, "type": "turn_end", "turn": 1, "exit_code": 0, "duration": 20},
            {"ts": 120, "type": "record", "record": {"kind": "assessment", "created": 120, "confidence": 0.8}},
            {"ts": 121, "type": "record", "record": {"kind": "decision", "created": 121, "strategy": "no_intervention"}},
        ]
        m = metrics.compute(events)
        self.assertEqual(m["defense"]["observed_events"], 2)      # baseline excluded
        self.assertEqual(m["defense"]["baseline_events"], 1)
        self.assertEqual(m["defense"]["elevated_events"], 1)
        self.assertEqual(m["defense"]["first_elevated_to_detection_s"], 19.0)
        self.assertEqual(m["driver"]["turns_triggered"], 1)
        self.assertEqual(m["driver"]["trigger_latency_mean_s"], 4.0)
        self.assertEqual(m["driver"]["turn_duration_mean_s"], 20.0)

    def test_anticipation_metrics(self):
        events = [
            {"ts": 100, "type": "record", "record": {"kind": "assessment", "created": 100, "confidence": 0.7,
                                                      "intent": "steal CI creds",
                                                      "predicted_next": [{"step": "read creds", "role": "jenkins",
                                                                          "asset": "/var/jenkins_home/credentials.xml"}]}},
            {"ts": 101, "type": "record", "record": {"kind": "decision", "created": 101, "strategy": "deception",
                                                      "preempts": "read creds"}},
            {"ts": 150, "type": "command", "plane": "attacker",
             "command": {"id": "a1", "side": "attacker", "command": "curl $JENKINS/credentials.xml", "created": 150,
                         "exit_code": 0, "status": "done"}},
        ]
        an = metrics.compute(events)["anticipation"]
        self.assertEqual(an["with_prediction"], 1)
        self.assertEqual(an["with_intent"], 1)
        self.assertEqual(an["preemptive_interventions"], 1)
        self.assertEqual(an["prediction_hit_rate"], 1.0)      # basename credentials.xml mentioned within 300 s


if __name__ == "__main__":
    unittest.main()
