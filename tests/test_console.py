"""Console completed-run replay and viewer protections (no server, Docker or network)."""
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import server  # noqa: E402


class StopTail(Exception):
    pass


def request_for(hub, path, body=None, headers=None):
    handler_type = server.make_handler(hub)
    request = handler_type.__new__(handler_type)
    request.path = path
    request.headers = {"Host": "127.0.0.1:8765", "Content-Type": "application/json",
                       **(headers or {})}
    request._body = lambda: body or {}
    request._json = mock.Mock()
    request.wfile = io.BytesIO()
    request.send_response = mock.Mock()
    request.send_header = mock.Mock()
    request.end_headers = mock.Mock()
    return request


class TailTest(unittest.TestCase):
    def test_replay_reads_existing_events_from_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "defense.jsonl"
            expected = [{"type": "record", "n": 1}, {"type": "record", "n": 2}]
            path.write_text("".join(json.dumps(ev) + "\n" for ev in expected), encoding="utf-8")
            seen = []
            with mock.patch.object(server.time, "sleep", side_effect=StopTail):
                with self.assertRaises(StopTail):
                    server.tail_jsonl(path, seen.append, replay=True)
            self.assertEqual(seen, expected)

    def test_default_still_tails_from_current_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "driver.jsonl"
            path.write_text(json.dumps({"type": "trigger", "turn": "old"}) + "\n", encoding="utf-8")
            seen = []
            sleeps = 0

            def controlled_sleep(_seconds):
                nonlocal sleeps
                sleeps += 1
                if sleeps == 1:
                    with path.open("a", encoding="utf-8") as f:
                        f.write(json.dumps({"type": "trigger", "turn": "new"}) + "\n")
                    return
                raise StopTail

            with mock.patch.object(server.time, "sleep", side_effect=controlled_sleep):
                with self.assertRaises(StopTail):
                    server.tail_jsonl(path, seen.append)
            self.assertEqual(seen, [{"type": "trigger", "turn": "new"}])

    def test_all_stream_wrappers_forward_replay(self):
        hub = mock.Mock()
        for tail in (server.tail_attacker_log, server.tail_defense_log,
                     server.tail_sensor_log, server.tail_driver_log):
            with self.subTest(tail=tail.__name__), mock.patch.object(server, "tail_jsonl") as follow:
                tail(hub, Path("stream.jsonl"), replay=True)
                self.assertTrue(follow.call_args.kwargs["replay"])


class RunLayoutTest(unittest.TestCase):
    def test_selected_run_dir_supplies_stream_defaults_and_preserves_empty_values(self):
        selected = Path(tempfile.gettempdir()) / "selected-completed-run"
        args = SimpleNamespace(run_dir=str(selected), attacker_log=None, defense_log=None,
                               sensor_log=None, driver_log=None)
        self.assertEqual(server.resolve_run_layout(args), selected)
        self.assertEqual(args.attacker_log, str(selected / "attacker" / "attacker.jsonl"))
        self.assertEqual(args.defense_log, str(selected / "defense" / "defense.jsonl"))
        self.assertEqual(args.sensor_log, str(selected / "defense" / "sensor.jsonl"))
        self.assertEqual(args.driver_log, str(selected / "defense" / "driver.jsonl"))

        disabled = SimpleNamespace(run_dir=str(selected), attacker_log="", defense_log="",
                                   sensor_log="", driver_log="")
        server.resolve_run_layout(disabled)
        self.assertEqual((disabled.attacker_log, disabled.defense_log,
                          disabled.sensor_log, disabled.driver_log), ("", "", "", ""))

    def test_operator_reset_and_export_stay_in_selected_run_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            selected = Path(tmp) / "completed-run"
            hub = server.Hub(selected, {"viewer": False})
            self.assertEqual(hub.run_dir, selected)
            self.assertEqual(hub.log_path.parent, selected / "console")

            reset = request_for(hub, "/api/reset")
            with mock.patch.object(hub, "new_session") as new_session:
                reset.do_POST()
            new_session.assert_called_once_with(selected)

            export = request_for(hub, "/api/export")
            with mock.patch.object(server.streams, "merge", return_value=[]) as merge:
                export.do_GET()
            merge.assert_called_once_with(selected)


class CustomStreamExportTest(unittest.TestCase):
    def test_merge_follows_custom_paths_and_honors_disabled_streams(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            state = runs / "defense-state"
            state.mkdir()
            (state / "defense.jsonl").write_text(json.dumps({"type": "record", "ts": 2}) + "\n")
            (state / "sensor.jsonl").write_text(json.dumps({"type": "observed", "ts": 3}) + "\n")
            (state / "driver.jsonl").write_text(json.dumps({"type": "trigger", "ts": 4}) + "\n")
            attacker = runs / "attackbox" / "attacker.jsonl"
            attacker.parent.mkdir()
            attacker.write_text(json.dumps({
                "event": "cmd", "id": "command-1", "command": "pwd", "ts": 1,
            }) + "\n")
            paths = {
                "defense": state / "defense.jsonl", "sensor": state / "sensor.jsonl",
                "driver": state / "driver.jsonl", "attacker": attacker,
            }
            events = server.streams.merge(runs, stream_paths=paths)
            self.assertEqual([event["type"] for event in events],
                             ["command", "record", "observed", "trigger"])
            disabled = {name: "" for name in paths}
            self.assertEqual(server.streams.merge(runs, stream_paths=disabled), [])

    def test_export_passes_the_actual_tail_paths_to_merge(self):
        with tempfile.TemporaryDirectory() as tmp:
            selected = Path(tmp)
            paths = {"defense": "/custom/defense.jsonl", "sensor": "",
                     "driver": "/custom/driver.jsonl", "attacker": "/custom/attacker.jsonl"}
            hub = server.Hub(selected, {"viewer": True, "stream_paths": paths})
            export = request_for(hub, "/api/export")
            with mock.patch.object(server.streams, "merge", return_value=[]) as merge:
                export.do_GET()
            merge.assert_called_once_with(selected, stream_paths=paths)

    def test_replay_export_includes_historical_events_from_custom_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            selected = Path(tmp)
            state = selected / "defense-state"
            state.mkdir()
            source_events = {
                "defense": [{"type": "record", "record": {"id": "r1"}, "ts": 1}],
                "driver": [
                    {"type": "trigger", "turn": 1, "ts": 2},
                    {"type": "turn_end", "turn": 1, "ts": 3},
                ],
            }
            paths = {"attacker": "", "sensor": ""}
            for name, events in source_events.items():
                path = state / f"{name}.jsonl"
                path.write_text("".join(json.dumps(ev) + "\n" for ev in events))
                paths[name] = path
            hub = server.Hub(selected, {
                "viewer": True, "replay": True, "stream_paths": paths,
            })
            export = request_for(hub, "/api/export")
            export.do_GET()
            exported = [json.loads(line) for line in export.wfile.getvalue().decode().splitlines()]
            self.assertEqual(
                [ev["type"] for ev in exported if ev.get("type") != "session"],
                ["record", "trigger", "turn_end"],
            )


class DisplayOutputTest(unittest.TestCase):
    def test_clean_output_strips_terminal_control_sequences(self):
        raw = ("\x1b[1;32mPORT\x1b[0m STATE\r\n22/tcp \x1b[32mopen\x1b[0m\n"
               "Progress: 10%\rProgress: 100%\n\x1b]0;title\x07ab\bc\x00d")
        self.assertEqual(server.clean_output(raw), "PORT STATE\n22/tcp open\nProgress: 100%\nacd")

    def test_browser_gets_clean_output_and_console_persists_no_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            hub = server.Hub(Path(tmp), {})
            q = server.queue.Queue()
            hub.subs.append(q)
            hub.commands["c1"] = {"id": "c1", "side": "defender", "via": "gateway", "command": "ls",
                                  "created": 1.0, "status": "done",
                                  "stdout": "\x1b[31mred\x1b[0m", "stderr": ""}
            hub.emit_cmd("c1")
            self.assertEqual(q.get_nowait()["command"]["stdout"], "red")
            persisted = [json.loads(line) for line in hub.log_path.read_text().splitlines()]
            self.assertEqual([e["type"] for e in persisted], ["session"])
            self.assertEqual(hub.snapshot()["commands"][0]["stdout"], "red")


class StreamIngestTest(unittest.TestCase):
    def test_observed_events_in_defense_stream_reach_the_defender_view(self):
        with tempfile.TemporaryDirectory() as tmp:
            hub = server.Hub(Path(tmp), {"viewer": True})
            ev = {"ts": 5.0, "type": "observed",
                  "event": {"index": 1, "ts": 5.0, "source": "gitea", "kind": "access-log",
                            "summary": "GET / 200", "raw": "x"}}
            hub.ingest_defense(ev)
            hub.ingest_sensor(ev)  # same event via sensor.jsonl is not duplicated
            self.assertEqual([o["index"] for o in hub.snapshot()["observed"]], [1])
            self.assertNotIn("raw", hub.snapshot()["observed"][0])

    def test_gateway_command_updates_replace_the_card(self):
        with tempfile.TemporaryDirectory() as tmp:
            hub = server.Hub(Path(tmp), {"viewer": True})
            base = {"id": "d1", "side": "defender", "via": "gateway", "command": "[jenkins] x",
                    "created": 1.0}
            hub.ingest_defense({"type": "command", "command": {**base, "status": "running"}})
            hub.ingest_defense({"type": "command", "command": {**base, "status": "done", "exit_code": 0}})
            self.assertEqual(hub.commands["d1"]["status"], "done")

    def test_attacker_log_is_processed_in_file_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            log = run / "attacker" / "attacker.jsonl"
            (log.parent / "out").mkdir(parents=True)
            lines = []
            for i in range(1, 30):
                lines.append({"ts": i, "event": "start", "id": f"c{i}", "command": f"cmd {i}"})
                lines.append({"ts": i + 0.5, "event": "end", "id": f"c{i}", "exit_code": 0})
            log.write_text("".join(json.dumps(ev) + "\n" for ev in lines))
            (log.parent / "out" / "c1.out").write_text("\x1b[32mok\x1b[0m")
            hub = server.Hub(run, {"viewer": True, "replay": True})
            with mock.patch.object(server.time, "sleep", side_effect=StopTail):
                with self.assertRaises(StopTail):
                    server.tail_attacker_log(hub, log, replay=True)
            cmds = sorted(hub.commands.values(), key=lambda c: c["turn"])
            self.assertEqual([c["command"] for c in cmds], [f"cmd {i}" for i in range(1, 30)])
            self.assertTrue(all(c["status"] == "done" for c in cmds))
            self.assertEqual(hub.snapshot()["commands"][0]["stdout"], "ok")

    def test_late_attacker_output_is_picked_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            out.mkdir()
            hub = server.Hub(Path(tmp), {"viewer": True})
            with mock.patch.object(server.threading, "Timer") as timer:
                hub.observe_attacker({"ts": 1, "event": "start", "id": "z", "command": "id"}, out)
                hub.observe_attacker({"ts": 2, "event": "end", "id": "z", "exit_code": 0}, out)
            (out / "z.out").write_text("uid=1000")
            hub._refresh_attacker_output(*timer.call_args.kwargs["args"])
            self.assertEqual(hub.commands["ab-z"]["stdout"], "uid=1000")

    def test_driver_failure_events_are_forwarded(self):
        with tempfile.TemporaryDirectory() as tmp:
            hub = server.Hub(Path(tmp), {"viewer": True})
            for t in ("trigger", "turn_end", "turn_retry", "driver_failed", "bounded_turn_profile"):
                hub.ingest_driver({"type": t, "turn": 1, "ts": 1})
            self.assertEqual([d["type"] for d in hub.snapshot()["triggers"]],
                             ["trigger", "turn_end", "turn_retry", "driver_failed"])

    def test_bad_record_does_not_stop_the_tailer(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.jsonl"
            path.write_text('{"n": 1}\n[1, 2]\n{"n": 2}\n{"n": 3}\n')
            seen = []

            def handler(ev):
                if ev["n"] == 2:
                    raise KeyError("boom")
                seen.append(ev["n"])

            with mock.patch.object(server.time, "sleep", side_effect=StopTail), \
                    mock.patch("builtins.print"):
                with self.assertRaises(StopTail):
                    server.tail_jsonl(path, handler, replay=True)
            self.assertEqual(seen, [1, 3])


class RequestOriginTest(unittest.TestCase):
    """New session is the only state-changing request left; it must not be cross-site."""
    def setUp(self):
        self.hub = mock.Mock()
        self.hub.cfg = {}

    def post(self, path, headers=None):
        request = request_for(self.hub, path, {}, headers)
        request.do_POST()
        return request._json.call_args.args

    def test_cross_site_and_rebinding_requests_are_refused(self):
        cases = {
            "text/plain CSRF": {"Content-Type": "text/plain"},
            "form CSRF": {"Content-Type": "application/x-www-form-urlencoded"},
            "foreign Origin": {"Origin": "http://evil.example"},
            "cross-site fetch": {"Sec-Fetch-Site": "cross-site"},
            "DNS rebinding Host": {"Host": "evil.example:8765"},
        }
        for name, headers in cases.items():
            with self.subTest(name):
                self.assertIn(self.post("/api/reset", headers)[1], (403, 421))
        self.hub.new_session.assert_not_called()

    def test_same_origin_new_session_is_accepted(self):
        args = self.post("/api/reset", {"Origin": "http://127.0.0.1:8765"})
        self.assertEqual(len(args), 1)          # 200 default
        self.hub.new_session.assert_called_once()

    def test_get_with_foreign_host_is_refused(self):
        request = request_for(self.hub, "/api/state", headers={"Host": "attacker.example"})
        request.do_GET()
        self.assertEqual(request._json.call_args.args[1], 421)


class AttackerOutputPathTest(unittest.TestCase):
    def test_ids_cannot_escape_the_output_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            out = base / "attacker" / "out"
            out.mkdir(parents=True)
            secret = base / "secret.out"
            secret.write_text("TOP-SECRET")
            (out / "link.out").symlink_to(secret)
            (out / "ok-1.out").write_text("fine")
            read = server.streams.read_output_file
            self.assertIsNone(read(out, "../../secret", "out"))
            self.assertIsNone(read(out, "/etc/passwd", "out"))
            self.assertIsNone(read(out, "link", "out"))          # symlink not followed
            self.assertEqual(read(out, "ok-1", "out"), (b"fine", False))
            hub = server.Hub(base, {"viewer": True})
            hub.observe_attacker({"ts": 1, "event": "start", "id": "../../secret", "command": "x"}, out)
            hub.observe_attacker({"ts": 2, "event": "end", "id": "../../secret", "exit_code": 0}, out)
            self.assertNotIn("TOP-SECRET", json.dumps(hub.snapshot()))
            events = server.streams.attacker_events(
                [{"ts": 1, "event": "cmd", "id": "../../secret", "command": "x"}], out)
            self.assertNotIn("TOP-SECRET", json.dumps(events))


class TargetHealthTest(unittest.TestCase):
    """Health comes from the sensor's container state; the Console never probes a target,
    so no host address or published port is assumed."""
    def test_reads_sensor_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            status = Path(tmp) / "sensor.status.json"
            targets = [{"name": "gitea", "container": "gitea", "state": "running", "health": "healthy", "up": True},
                       {"name": "prod", "container": "prod", "state": "exited", "health": None, "up": False}]
            status.write_text(json.dumps({"ts": server.time.time(), "targets": targets}))
            got = server.target_health(status)
            self.assertEqual([(t["name"], t["up"], t["status"]) for t in got],
                             [("gitea", True, "healthy"), ("prod", False, "exited")])
            status.write_text(json.dumps({"ts": 1, "targets": targets}))      # sensor stopped
            self.assertFalse(any(t["up"] for t in server.target_health(status)))
        self.assertEqual(server.target_health(""), [])
        self.assertEqual(server.target_health("/nonexistent/sensor.status.json"), [])

    def test_sensor_phase(self):
        with tempfile.TemporaryDirectory() as tmp:
            status = Path(tmp) / "sensor.status.json"
            self.assertEqual(server.sensor_phase(""), {"phase": "off"})
            self.assertEqual(server.sensor_phase(status)["phase"], "starting")
            status.write_text(json.dumps({"ts": server.time.time(), "baseline": {
                "state": "learning", "elapsed_sec": 45.2, "duration_sec": 120}}))
            self.assertEqual(server.sensor_phase(status),
                             {"phase": "learning", "elapsed_sec": 45.2, "duration_sec": 120})
            status.write_text(json.dumps({"ts": server.time.time(), "baseline": {"state": "ready", "learned": 9}}))
            self.assertEqual(server.sensor_phase(status)["phase"], "watching")
            status.write_text(json.dumps({"ts": 1, "baseline": {"state": "ready"}}))
            self.assertEqual(server.sensor_phase(status)["phase"], "stale")

    def test_console_has_no_network_probe(self):
        self.assertFalse(hasattr(server, "socket"))
        self.assertFalse(hasattr(server, "check_targets"))


class RemovedOperatorModeTest(unittest.TestCase):
    def test_command_endpoints_are_gone(self):
        hub = mock.Mock()
        hub.cfg = {}
        request = request_for(hub, "", {"side": "attacker", "command": "echo must-not-run",
                                        "action": "release", "kind": "assessment"})
        for path in ("/api/exec", "/api/gate", "/api/held/command-id", "/api/record", "/api/turn"):
            with self.subTest(path=path):
                request.path = path
                request._json.reset_mock()
                request.do_POST()
                self.assertEqual(request._json.call_args.args[1], 404)
        self.assertFalse(hasattr(server, "subprocess"))     # the console cannot run commands
        for name in ("submit", "operate", "set_gate", "record"):
            self.assertFalse(hasattr(server.Hub, name), name)

    def test_snapshot_has_no_operator_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            snap = server.Hub(Path(tmp), {"scenario": "x"}).snapshot()
        self.assertNotIn("gate_hold", snap)
        self.assertNotIn("samples", snap["config"])


if __name__ == "__main__":
    unittest.main()


class ImportExportTest(unittest.TestCase):
    """`server.py --import` / `live_demo.py view`: an exported run is reviewed offline."""

    def export_rows(self):
        cmd = {"id": "ab-1", "side": "attacker", "command": "ls", "created": 10.0, "status": "done", "exit_code": 0}
        return [
            {"ts": 1.0, "plane": "console", "type": "session", "session": "x"},
            {"ts": 10.0, "plane": "attacker", "type": "command", "command": cmd},
            {"ts": 11.0, "plane": "defense", "type": "observed",
             "event": {"index": 5, "ts": 11.0, "source": "gitea", "kind": "new-source", "level": "elevated",
                       "summary": "first request"}},
            {"ts": 12.0, "plane": "defense", "type": "trigger", "turn": 1, "reason": "elevated"},
            {"ts": 13.0, "plane": "defense", "type": "record",
             "record": {"id": "r1", "kind": "decision", "created": 13.0, "strategy": "containment", "turn": 1}},
            {"ts": 14.0, "plane": "defense", "type": "action_observation", "action_id": "a1",
             "observation": {"record_type": "containment_observation", "status": "verified",
                             "surface": "workload"}},
        ]

    def test_import_fills_every_pane_and_export_returns_the_imported_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "run-merged.jsonl"
            rows = self.export_rows()
            path.write_text("".join(json.dumps(r) + "\n" for r in reversed(rows)), encoding="utf-8")
            hub = server.Hub(Path(tmp) / "scratch", {"replay": True})
            self.assertEqual(server.import_export(hub, path), 5)          # the console marker is skipped
            snap = hub.snapshot()
            self.assertEqual([c["id"] for c in snap["commands"]], ["ab-1"])
            self.assertEqual([e["index"] for e in snap["observed"]], [5])
            self.assertEqual([d["turn"] for d in snap["triggers"]], [1])
            self.assertEqual([r["id"] for r in snap["records"]], ["r1"])
            self.assertEqual(snap["outcomes"][0]["status"], "verified")
            self.assertTrue(snap["config"]["imported"])
            req = request_for(hub, "/api/export")
            server.make_handler(hub).do_GET(req)
            exported = [json.loads(l) for l in req.wfile.getvalue().decode().splitlines()]
            self.assertEqual(len(exported), len(rows))                     # same run, re-exportable
            reset = request_for(hub, "/api/reset", body={}, headers={"Origin": "http://127.0.0.1:8765"})
            reset._post_ok = lambda: None
            server.make_handler(hub).do_POST(reset)
            self.assertEqual(reset._json.call_args.args[1], 409)          # nothing to reset offline
