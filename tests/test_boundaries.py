"""Attack Box egress proxy, Docker API guard, and attacker env minimization (no Docker)."""
import asyncio
import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


egress = load("egress_proxy", "egress/egress_proxy.py")
guard = load("docker_api_guard", "apiguard/docker_api_guard.py")


class EgressPolicyTest(unittest.TestCase):
    def setUp(self):
        self.p = egress.Policy("opencode.ai,.amazonaws.com,llm.lab:8001")

    def test_only_allow_listed_llm_hosts_on_443(self):
        self.assertIsNone(self.p.match("opencode.ai", 443))
        self.assertIsNone(self.p.match("OpenCode.AI.", 443))
        self.assertIsNone(self.p.match("bedrock-runtime.us-east-1.amazonaws.com", 443))
        self.assertIsNone(self.p.match("llm.lab", 8001))
        for host, port, why in [("www.google.com", 443, "host-not-allowed"),
                                ("api.search.brave.com", 443, "host-not-allowed"),
                                ("opencode.ai.evil.com", 443, "host-not-allowed"),
                                ("evilopencode.ai", 443, "host-not-allowed"),
                                ("amazonaws.com", 443, "host-not-allowed"),
                                ("opencode.ai", 80, "port-not-allowed"),
                                ("llm.lab", 443, "port-not-allowed"),
                                ("1.1.1.1", 443, "ip-literal"),
                                ("[::1]", 443, "ip-literal"),
                                ("bad_host!", 443, "bad-host")]:
            with self.subTest(host=host, port=port):
                self.assertEqual(self.p.match(host, port), why)

    def test_private_and_metadata_addresses_are_not_public(self):
        for addr in ("10.0.0.1", "172.17.0.1", "192.168.1.1", "127.0.0.1", "169.254.169.254",
                     "::1", "fd00::1", "::ffff:127.0.0.1", "100.64.0.1", "0.0.0.0"):
            with self.subTest(addr=addr):
                self.assertFalse(egress.public_address(addr))
        self.assertTrue(egress.public_address("1.1.1.1"))

    def test_only_connect_is_parsed(self):
        self.assertEqual(egress.parse_connect(b"CONNECT opencode.ai:443 HTTP/1.1\r\n"), ("opencode.ai", 443))
        for bad in (b"GET http://example.com/ HTTP/1.1\r\n", b"CONNECT opencode.ai HTTP/1.1\r\n",
                    b"CONNECT opencode.ai:99999 HTTP/1.1\r\n", b"CONNECT a:443 SPDY/3\r\n"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                egress.parse_connect(bad)


class EgressProxyRunTest(unittest.TestCase):
    def setUp(self):
        self.logged = []

    def run_case(self, request: bytes, resolved: list[str], allow_private=""):
        async def main():
            upstream_seen = []

            async def upstream(reader, writer):
                upstream_seen.append(await reader.read(5))
                writer.write(b"pong!")
                await writer.drain()
                writer.close()

            up = await asyncio.start_server(upstream, "127.0.0.1", 0)
            port = up.sockets[0].getsockname()[1]

            async def resolver(host, _port):
                return resolved

            policy = egress.Policy(f"llm.test:{port}", allow_private)
            proxy = egress.EgressProxy(policy, resolver=resolver, idle=5)
            proxy.log = lambda **ev: self.logged.append(ev)
            srv = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
            pport = srv.sockets[0].getsockname()[1]
            r, w = await asyncio.open_connection("127.0.0.1", pport)
            w.write(request.replace(b"PORT", str(port).encode()))
            await w.drain()
            status = (await r.readline()).decode().strip()
            body = b""
            if " 200 " in status:
                await r.readline()
                w.write(b"ping!")
                await w.drain()
                body = await r.read(5)
            w.close()
            srv.close()
            up.close()
            return status, body, upstream_seen

        return asyncio.run(main())

    def test_tunnel_to_allowed_host(self):
        status, body, seen = self.run_case(b"CONNECT llm.test:PORT HTTP/1.1\r\n\r\n", ["127.0.0.1"], "llm.test")
        self.assertIn("200", status)
        self.assertEqual((body, seen), (b"pong!", [b"ping!"]))
        # Logged when the tunnel opens: an LLM session keeps one tunnel open for its whole run.
        self.assertEqual([e["decision"] for e in self.logged][:1], ["allow"])

    def test_allowed_name_resolving_to_private_address_is_refused(self):
        # DNS rebinding / a hostile record pointing an approved name at the host or metadata.
        status, _, seen = self.run_case(b"CONNECT llm.test:PORT HTTP/1.1\r\n\r\n", ["127.0.0.1"])
        self.assertIn("403", status)
        self.assertEqual(seen, [])

    def test_plain_http_and_unlisted_hosts_are_refused(self):
        for req in (b"GET http://llm.test:PORT/ HTTP/1.1\r\nHost: llm.test\r\n\r\n",
                    b"CONNECT www.google.com:443 HTTP/1.1\r\n\r\n"):
            with self.subTest(req=req):
                status, _, seen = self.run_case(req, ["127.0.0.1"], "llm.test")
                self.assertIn("403", status)
                self.assertEqual(seen, [])


class EgressUpstreamTest(unittest.TestCase):
    def test_allowed_tunnel_goes_through_corporate_proxy_with_auth(self):
        async def main():
            seen = {}

            async def corp_proxy(reader, writer):        # stands in for a corporate proxy
                seen["head"] = await reader.readuntil(b"\r\n\r\n")
                writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await writer.drain()
                seen["payload"] = await reader.read(5)
                writer.write(b"pong!")
                await writer.drain()
                writer.close()

            corp = await asyncio.start_server(corp_proxy, "127.0.0.1", 0)
            cport = corp.sockets[0].getsockname()[1]

            async def no_dns(host, port):                 # corporate DNS may not resolve it
                raise OSError("no resolution")

            proxy = egress.EgressProxy(egress.Policy("opencode.ai"), resolver=no_dns, idle=5,
                                       upstream=egress.parse_upstream(f"http://u%40x:p@127.0.0.1:{cport}"))
            proxy.log = lambda **ev: None
            srv = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
            pport = srv.sockets[0].getsockname()[1]
            out = {}
            for host in ("opencode.ai", "www.google.com"):
                r, w = await asyncio.open_connection("127.0.0.1", pport)
                w.write(f"CONNECT {host}:443 HTTP/1.1\r\n\r\n".encode())
                await w.drain()
                status = (await r.readline()).decode()
                if " 200 " in status:
                    await r.readline()
                    w.write(b"ping!")
                    await w.drain()
                    out[host] = (status, await r.read(5))
                else:
                    out[host] = (status, b"")
                w.close()
            srv.close()
            corp.close()
            return out, seen

        out, seen = asyncio.run(main())
        self.assertIn(" 200 ", out["opencode.ai"][0])
        self.assertEqual(out["opencode.ai"][1], b"pong!")
        self.assertTrue(seen["head"].startswith(b"CONNECT opencode.ai:443 HTTP/1.1"))
        self.assertIn(b"Proxy-Authorization: Basic dUB4OnA=", seen["head"])
        self.assertIn(" 403 ", out["www.google.com"][0])           # allowlist still applies


class ApiGuardRuleTest(unittest.TestCase):
    def test_only_the_gateway_endpoints_are_allowed(self):
        allowed = [("HEAD", "/_ping"), ("GET", "/v1.47/version"), ("GET", "/v1.47/containers/json"),
                   ("GET", "/v1.47/containers/gitea/json"), ("GET", "/containers/abc123/logs"),
                   ("GET", "/v1.47/containers/prod/changes"),
                   ("POST", "/v1.47/containers/jenkins-server/exec"),
                   ("POST", "/v1.47/exec/" + "a" * 64 + "/start"), ("GET", "/exec/" + "b" * 64 + "/json")]
        denied = [("POST", "/v1.47/containers/create"), ("POST", "/containers/gitea/start"),
                  ("POST", "/containers/gitea/kill"), ("DELETE", "/containers/gitea"),
                  ("PUT", "/containers/gitea/archive"), ("GET", "/containers/gitea/archive"),
                  ("POST", "/containers/gitea/update"), ("GET", "/images/json"),
                  ("POST", "/images/create"), ("POST", "/networks/x/connect"), ("POST", "/build"),
                  ("GET", "/containers/gitea/export"), ("POST", "/volumes/create"),
                  ("GET", "/containers/../images/json"), ("GET", "/containers/a%2Fb/json"),
                  ("GET", "//containers/json"), ("POST", "/containers/gitea/exec/../create")]
        for m, p in allowed:
            with self.subTest(allowed=(m, p)):
                self.assertTrue(guard.match_rule(m, p)[0])
        for m, p in denied:
            with self.subTest(denied=(m, p)):
                self.assertFalse(guard.match_rule(m, p)[0])

    def test_exec_checks(self):
        g = guard.Guard(exec_containers={"gitea"})
        infos = {
            "gitea": {"Name": "/gitea", "Id": "1" * 64, "HostConfig": {}, "Mounts": []},
            "other": {"Name": "/other", "Id": "2" * 64, "HostConfig": {}, "Mounts": []},
            "priv": {"Name": "/gitea", "Id": "3" * 64, "HostConfig": {"Privileged": True}, "Mounts": []},
            "sock": {"Name": "/gitea", "Id": "4" * 64, "HostConfig": {},
                     "Mounts": [{"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}]},
            "plane": {"Name": "/antigent-core", "Id": "5" * 64, "HostConfig": {}, "Mounts": []},
        }

        async def fake_get(path):
            return 200, infos[path.split("/")[2]]

        g.docker_get = fake_get
        check = lambda ref, body=b'{"Cmd":["id"]}': asyncio.run(g.check_exec(ref, body))
        self.assertIsNone(check("gitea"))
        self.assertIn("privileged exec", check("gitea", b'{"Cmd":["id"],"Privileged":true}'))
        self.assertIn("not an allow-listed", check("other"))
        self.assertIn("is privileged", check("priv"))
        self.assertIn("Docker socket", check("sock"))
        self.assertIn("Antigent plane", check("plane"))
        self.assertIn("not JSON", check("gitea", b"{"))


class AttackerEnvTest(unittest.TestCase):
    def build(self, **cfg):
        from demo.config import DemoConfig
        from demo.docker_ops import DemoOrchestrator
        base = dict(cicd_goat_dir=ROOT, defense_plane_dir=ROOT, run_dir=ROOT / "runs" / "t",
                    attacker_model="opencode/glm-5.3-flash-free",
                    defender_model="opencode/glm-5.3-flash-free")
        base.update(cfg)
        return DemoOrchestrator(DemoConfig(**base))._build_attack_env()

    def test_free_model_injects_no_credentials_even_if_inherited(self):
        polluted = {"ATTACKER_LLM_API_KEY": "sk-leftover", "ATTACKER_AWS_SECRET_ACCESS_KEY": "x",
                    "ATTACKER_EGRESS_ALLOW": ".com", "ATTACKER_EGRESS_ALLOW_PRIVATE": "evil"}
        with mock.patch.dict(os.environ, polluted):
            env = self.build()
        for key in ("ATTACKER_LLM_API_KEY", "ATTACKER_AWS_SECRET_ACCESS_KEY",
                    "ATTACKER_AWS_BEARER_TOKEN_BEDROCK", "ATTACKER_EGRESS_ALLOW_PRIVATE"):
            self.assertEqual(env[key], "", key)
        self.assertEqual(env["ATTACKER_EGRESS_ALLOW"], "opencode.ai")

    def test_bedrock_attacker_never_gets_defender_credential_by_default(self):
        cfg = dict(attacker_model="amazon-bedrock/x", aws_bearer_token_bedrock="DEFENDER",
                   aws_access_key_id="AKIADEF", aws_secret_access_key="defsecret")
        env = self.build(**cfg)
        self.assertNotIn("DEFENDER", env.values())
        self.assertNotIn("defsecret", env.values())
        env = self.build(**cfg, attacker_aws_bearer_token_bedrock="ATTACKER",
                         attacker_aws_access_key_id="AKIAATT", attacker_aws_secret_access_key="att")
        self.assertEqual(env["ATTACKER_AWS_BEARER_TOKEN_BEDROCK"], "ATTACKER")
        self.assertEqual(env["ATTACKER_AWS_SECRET_ACCESS_KEY"], "")      # never both forms
        self.assertEqual(env["ATTACKER_EGRESS_ALLOW"], "bedrock-runtime.us-east-1.amazonaws.com")

    def test_renamed_lab_containers_are_followed(self):
        with mock.patch.dict(os.environ, {"GITEA_CONTAINER": "lab-gitea", "PROD_CONTAINER": "lab-prod"}):
            env = self.build()
        targets = env["AUTHORIZED_TARGETS"].split(",")
        self.assertIn("lab-gitea", targets)
        self.assertIn("lab-prod", targets)
        self.assertNotIn("gitea", targets)

    def test_openai_attacker_gets_only_its_own_key_and_host(self):
        env = self.build(attacker_model="openai/gpt-x", openai_attacker_key="sk-att",
                         openai_defender_key="sk-def")
        self.assertEqual(env["ATTACKER_LLM_API_KEY"], "sk-att")
        self.assertNotIn("sk-def", env.values())
        self.assertEqual(env["ATTACKER_EGRESS_ALLOW"], "api.openai.com")


class RunnerDiagnosticsTest(unittest.TestCase):
    def test_no_attacker_commands_is_explained(self):
        import io
        import json
        import tempfile
        from contextlib import redirect_stdout
        from demo.config import DemoConfig
        from demo.runner import DemoRunner
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "runs" / "attacker").mkdir(parents=True)
            (root / "runs" / "egress").mkdir(parents=True)
            (root / "runs" / "attacker" / "attacker.jsonl").write_text("")
            (root / "runs" / "attacker" / "opencode.out").write_text('{"type":"error","error":"model not found"}\n')
            (root / "runs" / "egress" / "egress.jsonl").write_text(json.dumps(
                {"ts": 10, "host": "opencode.ai", "port": 443, "decision": "deny", "reason": "connect-failed"}) + "\n")
            cfg = DemoConfig(cicd_goat_dir=root, defense_plane_dir=root, run_dir=root / "runs" / "demo",
                             attacker_model="opencode/x", defender_model="opencode/x")
            runner = DemoRunner(cfg)
            runner.orchestrator.attack_exit_code = lambda: 1
            runner._attack_t0 = 0
            buf = io.StringIO()
            with redirect_stdout(buf):
                runner._diagnose_attack()
            text = buf.getvalue()
        self.assertIn("ran no shell commands", text)
        self.assertIn("ATTACKER_EGRESS_UPSTREAM_PROXY", text)
        self.assertIn("model not found", text)
        self.assertIn("exit code: 1", text)


class AttackboxComposeTest(unittest.TestCase):
    def test_opencode_does_not_reach_for_the_model_catalog(self):
        text = (ROOT / "examples" / "attacker" / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn('OPENCODE_DISABLE_MODELS_FETCH: "1"', text)
        self.assertIn('OPENCODE_DISABLE_AUTOUPDATE: "1"', text)


class RunnerStatusLineTest(unittest.TestCase):
    def test_open_tunnel_and_refused_hosts_are_shown(self):
        import json
        import tempfile
        from demo.config import DemoConfig
        from demo.runner import DemoRunner
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "runs" / "attacker").mkdir(parents=True)
            (root / "runs" / "egress").mkdir(parents=True)
            (root / "runs" / "attacker" / "attacker.jsonl").write_text(
                json.dumps({"ts": 11, "event": "cmd", "cmd": "id"}) + "\n")
            rows = [{"ts": 10, "host": "opencode.ai", "port": 443, "decision": "allow"},
                    {"ts": 10, "host": "models.dev", "port": 443, "decision": "deny", "reason": "host-not-allowed"},
                    {"ts": 12, "host": "models.dev", "port": 443, "decision": "deny", "reason": "host-not-allowed"}]
            (root / "runs" / "egress" / "egress.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
            cfg = DemoConfig(cicd_goat_dir=root, defense_plane_dir=root, run_dir=root / "runs" / "demo",
                             attacker_model="opencode/x", defender_model="opencode/x")
            runner = DemoRunner(cfg)
            runner._attack_t0 = 0
            line = runner._status_line()
        self.assertIn("attacker commands: 1", line)
        self.assertIn("1 opened (1 open)", line)
        self.assertIn("2 refused [models.dev]", line)


class DefenseRecoveryLifecycleTest(unittest.TestCase):
    @staticmethod
    def config(root):
        from demo.config import DemoConfig
        return DemoConfig(cicd_goat_dir=root, defense_plane_dir=root, run_dir=root / "runs" / "demo",
                          attacker_model="opencode/x", defender_model="opencode/x")

    def test_finalize_pauses_driver_and_requires_accepted_receipt(self):
        import json
        import tempfile
        import demo.docker_ops as d
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.config(Path(tmp))
            defense = cfg.run_dir / "defense"
            defense.mkdir(parents=True)
            (defense / "driver.state.json").write_text("{}")
            receipt = {"schema_version": "final_reobservation_v1", "accepted": True,
                       "final_reobserved_action_ids": []}

            def finish_turn(_seconds):
                (defense / "driver.finalized.json").write_text(json.dumps(receipt))

            with mock.patch.object(d.time, "monotonic", return_value=0), \
                    mock.patch.object(d.time, "sleep", side_effect=finish_turn):
                result = d.DemoOrchestrator(cfg).finalize_defense(120)
            self.assertTrue(result["accepted"])
            self.assertTrue((defense / "driver.pause").is_file())
            self.assertTrue((defense / "driver.finalize").is_file())

    def test_recovery_invokes_adapter_once_and_reuses_complete_report(self):
        import json
        import tempfile
        import demo.docker_ops as d
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.config(Path(tmp))
            defense = cfg.run_dir / "defense"
            defense.mkdir(parents=True)
            (defense / "intervention_state.json").write_text(
                json.dumps({"reservations": [{"action_id": "a000000001"}]}))
            report = {"schema_version": "defense_recovery_report_v1", "complete": True,
                      "recoveries": [{"action_id": "a000000001", "status": "restored"}],
                      "containment_final": []}
            calls = []

            def fake_compose(args, project_dir, env=None, check=True, compose_file="compose.yaml"):
                calls.append(args)
                (defense / "recovery.json").write_text(json.dumps(report))
                return ""

            orch = d.DemoOrchestrator(cfg)
            with mock.patch.object(d, "run_compose", fake_compose):
                self.assertEqual(orch.recover_defense(), report)
                self.assertEqual(orch.recover_defense(), report)  # stop is idempotent
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][:5], ["exec", "-T", "antigent", "python3",
                                            "/antigent/scenarios/cicd-goat/adapter.py"])
            self.assertIn("recover", calls[0])

    def test_incomplete_recovery_is_not_silent_and_shutdown_still_runs(self):
        import json
        import tempfile
        import demo.docker_ops as d
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.config(Path(tmp))
            defense = cfg.run_dir / "defense"
            defense.mkdir(parents=True)
            (defense / "intervention_state.json").write_text(
                json.dumps({"reservations": [{"action_id": "a000000001"}]}))

            def incomplete(args, project_dir, env=None, check=True, compose_file="compose.yaml"):
                (defense / "recovery.json").write_text(json.dumps({
                    "schema_version": "defense_recovery_report_v1", "complete": False,
                    "recoveries": [], "containment_final": []}))
                return ""

            orch = d.DemoOrchestrator(cfg)
            with mock.patch.object(d, "run_compose", incomplete):
                with self.assertRaisesRegex(d.DockerError, "recovery.*incomplete"):
                    orch.recover_defense()
            with mock.patch.object(orch, "recover_defense", side_effect=d.DockerError("incomplete")) as recover, \
                    mock.patch.object(d, "run_compose", return_value="") as compose:
                orch.stop_defense()
            recover.assert_called_once_with()
            self.assertEqual(compose.call_args.args[0], ["down"])


class FreshRunStateTest(unittest.TestCase):
    def test_previous_run_is_archived_not_deleted(self):
        import tempfile
        from demo.docker_ops import archive_run_dir
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp) / "demo"
            (run / "defense").mkdir(parents=True)
            (run / "defense" / "driver.state.json").write_text('{"turn": 89}')
            (run / "defense" / "sensor.status.json").write_text('{"baseline": {"ready": true}}')
            first = archive_run_dir(run)
            self.assertFalse(run.exists())
            self.assertEqual((first / "defense" / "driver.state.json").read_text(), '{"turn": 89}')
            run.mkdir()
            self.assertIsNone(archive_run_dir(run))                  # empty: nothing to archive
            (run / "x").write_text("1")
            second = archive_run_dir(run)
            self.assertNotEqual(first, second)                       # never overwrites an archive

    def test_stale_baseline_status_is_not_accepted(self):
        import json
        import tempfile
        import demo.docker_ops as d
        from demo.config import DemoConfig
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = DemoConfig(cicd_goat_dir=root, defense_plane_dir=root, run_dir=root / "runs" / "demo",
                             attacker_model="opencode/x", defender_model="opencode/x")
            status = cfg.run_dir / "defense" / "sensor.status.json"
            status.parent.mkdir(parents=True)
            status.write_text(json.dumps({"baseline": {"ready": True}}))
            os.utime(status, (1, 1))                                 # left over from an old run

            def fake_compose(args, project_dir, env=None, check=True, compose_file="compose.yaml"):
                return ""

            clock = iter(range(0, 10_000, 30))
            with mock.patch.object(d, "run_compose", fake_compose), \
                    mock.patch.object(d.time, "monotonic", lambda: next(clock)), \
                    mock.patch.object(d.time, "sleep", lambda s: None):
                ok = d.DemoOrchestrator(cfg).start_defense()
            self.assertFalse(ok)                                     # times out instead of skipping
            archived = [p for p in (root / "runs").iterdir() if p.name.startswith("demo-")]
            self.assertEqual(len(archived), 1)


if __name__ == "__main__":
    unittest.main()
