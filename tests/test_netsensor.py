"""v0.17 netsensor: frame/HTTP parsing, request/response pairing, and sensor-daemon ingestion
(role mapping, internal rule, access-log dedup). No Docker, no raw sockets.
  python -m unittest discover -s tests -v
"""
import base64
import json
import os
import socket
import struct
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gateway"))
os.environ.setdefault("ANTIGENT_SCENARIO", str(ROOT / "scenarios" / "cicd-goat"))
import defense_gateway as gw  # noqa: E402
import netsensor as ns  # noqa: E402
from baseline import CleanBaseline  # noqa: E402


def frame(src, sport, dst, dport, flags=0x18, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 1, 5 << 4, flags, 65535, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), 0, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip + tcp + payload


A, J = "172.19.0.1", "172.19.0.10"   # attacker as seen on the bridge, jenkins-server


class ParseTest(unittest.TestCase):
    def test_frame_and_request(self):
        cred = base64.b64encode(b"alice:S3cret!").decode()
        req = (f"GET /job/x/api/json?tree=jobs&token=abc HTTP/1.1\r\nHost: localhost:8080\r\n"
               f"Authorization: Basic {cred}\r\nCookie: JSESSIONID=zzz\r\n\r\n").encode()
        p = ns.parse_frame(frame(A, 50000, J, 8080, payload=req))
        self.assertEqual((p["src"], p["dst"], p["dport"]), (A, J, 8080))
        r = ns.parse_request(p["payload"])
        self.assertEqual(r["method"], "GET")
        self.assertEqual(r["path"], "/job/x/api/json?tree=jobs&token=***")
        self.assertEqual(r["user"], "alice")
        self.assertNotIn("S3cret", json.dumps(r))          # never the password
        self.assertNotIn("zzz", json.dumps(r))             # never cookies
        self.assertIsNone(ns.parse_request(b"\x16\x03\x01\x00"))

    def test_pairing_and_conn(self):
        tr = ns.Tracker(conn_wait=3, resp_wait=10)
        self.assertEqual(tr.feed(ns.parse_frame(frame(A, 50000, J, 8080, 0x02)), 100), [])
        tr.feed(ns.parse_frame(frame(A, 50000, J, 8080, payload=b"GET /login HTTP/1.1\r\nHost: x\r\n\r\n")), 100.1)
        out = tr.feed(ns.parse_frame(frame(J, 8080, A, 50000, payload=b"HTTP/1.1 403 Forbidden\r\n\r\n")), 100.2)
        self.assertEqual([(o["type"], o["path"], o["status"]) for o in out], [("http", "/login", "403")])
        dup = tr.feed(ns.parse_frame(frame(J, 8080, A, 50000, payload=b"HTTP/1.1 403 Forbidden\r\n\r\n")), 100.2)
        self.assertEqual(dup, [])                            # same segment twice (loopback / retransmit)
        self.assertEqual(tr.tick(200), [])                   # the SYN was consumed by the HTTP flow
        # SSH: server speaks first
        tr.feed(ns.parse_frame(frame(A, 50001, "172.19.0.6", 22, 0x02)), 101)
        out = tr.feed(ns.parse_frame(frame("172.19.0.6", 22, A, 50001, payload=b"SSH-2.0-OpenSSH_9\r\n")), 101.1)
        self.assertEqual(out[0]["proto"], "ssh")
        # port scan: SYN -> RST
        tr.feed(ns.parse_frame(frame(A, 50002, J, 5432, 0x02)), 102)
        out = tr.feed(ns.parse_frame(frame(J, 5432, A, 50002, 0x14)), 102.01)
        self.assertEqual((out[0]["type"], out[0]["proto"]), ("conn", "refused"))
        # silent connection -> reported after conn_wait; request without answer after resp_wait
        tr.feed(ns.parse_frame(frame(A, 50003, J, 50000, 0x02)), 103)
        tr.feed(ns.parse_frame(frame(A, 50004, J, 8080, payload=b"POST /x HTTP/1.1\r\n\r\n")), 103)
        out = tr.tick(107)
        self.assertEqual([o["type"] for o in out], ["conn"])
        out = tr.tick(114)
        self.assertEqual((out[0]["type"], out[0].get("status")), ("http", None))


def driver_is_activity(ev):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "gateway"))
    import driver
    return driver.is_activity(ev)


class FakeObs(gw.Observer):
    def __init__(self):
        self.out = []
        super().__init__(sink=self.out.append)
        self._internal = {J, "172.19.0.5"}    # scenario "internal" (same compose project)
        self._internal_at = 1e18
        self._net_map = {"172.19.0.2": "gitea", J: "jenkins", "172.19.0.30": "ctfd"}
        self._net_map_at = 1e18
        self._gw = {"172.19.0.254"}           # target network gateway (the Linux Docker host)
        self._gw_at = 1e18


class IngestTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "flows.jsonl"
        self.path.write_text(json.dumps({"ts": 1, "type": "http", "src": A, "dst": J, "dport": 8080,
                                         "method": "GET", "path": "/old"}) + "\n")
        self._old = gw.NET_STREAM
        gw.NET_STREAM = self.path

    def tearDown(self):
        gw.NET_STREAM = self._old
        self.tmp.cleanup()

    def write(self, recs):
        with open(self.path, "a") as f:
            for r in recs:
                f.write(json.dumps(r) + "\n")

    def test_ingest(self):
        o = FakeObs()
        o._collect_net()                       # existing history is skipped
        self.assertEqual(o.out, [])
        t = 2000.0
        recs = [{"ts": t + i, "type": "http", "src": A, "sport": 40000 + i, "dst": J, "dport": 8080,
                 "method": "GET", "path": f"/job/j{i}/", "status": "404"} for i in range(10)]
        recs.append({"ts": t + 11, "type": "http", "src": A, "dst": J, "dport": 8080, "method": "GET",
                     "path": "/me", "status": "401", "user": "admin"})
        recs.append({"ts": t + 12, "type": "conn", "src": A, "dst": "172.19.0.30", "dport": 8000, "proto": "tcp"})
        recs.append({"ts": t + 13, "type": "http", "src": J, "dst": "172.19.0.2", "dport": 3000,
                     "method": "GET", "path": "/scan", "status": "200"})          # jenkins -> gitea: internal
        recs.append({"ts": t + 14, "type": "http", "src": A, "dst": "172.17.0.9", "dport": 80,
                     "method": "GET", "path": "/", "status": "200"})              # not a target container
        self.write(recs)
        o._collect_net()
        o._flush_auth(force=True)
        kinds = [(e["source"], e["kind"]) for e in o.out]
        self.assertIn(("jenkins", "new-source"), kinds)
        self.assertIn(("jenkins", "recon-burst"), kinds)
        self.assertIn(("jenkins", "error-burst"), kinds)
        self.assertIn(("jenkins", "auth-failure"), kinds)
        self.assertIn(("ctfd", "new-source"), kinds)
        http = [e for e in o.out if e["kind"] == "net-http"]
        self.assertEqual(len(http), 11)
        self.assertTrue(all(e["client"] == A and e["via"] == "netsensor" for e in http))
        self.assertIn("basic user admin", http[-1]["summary"])
        ctfd = [e for e in o.out if e["kind"] == "net-conn"][0]
        self.assertTrue(ctfd["observe_only"])
        self.assertFalse(any(e["source"] == "gitea" for e in o.out))   # internal dropped
        self.assertEqual(o.net_stats["internal"], 1)
        self.assertEqual(o.net_stats["untargeted"], 1)

    def test_docker_host_traffic_is_not_attacker_activity(self):
        # The target network's gateway (the Docker host on Linux) is found at run time and is
        # internal. No address is hard-coded: a Docker Desktop VM address counts only when the
        # operator lists it in ANTIGENT_HOST_ADDRESSES.
        def run(host_addresses):
            o = FakeObs()
            o._collect_net()
            o.out.clear()
            recs = [{"ts": 4000 + i, "type": "conn", "src": src, "dst": "172.19.0.2", "dport": 3000, "kind": "tcp"}
                    for i, src in enumerate(["192.168.65.1", "172.19.0.254"] * 3)]
            recs.append({"ts": 4100, "type": "conn", "src": "172.31.0.2", "dst": "172.19.0.2", "dport": 3000, "kind": "tcp"})
            self.write(recs)
            with mock.patch.object(gw, "HOST_ADDRESSES", host_addresses):
                o._collect_net()
            return {e.get("client") for e in o.out if not e.get("internal") and e.get("client")}

        self.assertEqual(run(set()), {"192.168.65.1", "172.31.0.2"})          # default: nothing assumed
        self.write([])
        self.assertEqual(run({"192.168.65.1"}), {"172.31.0.2"})               # configured: host traffic internal

    def test_own_marked_requests_make_their_source_internal(self):
        # Antigent's Jenkins client reaches the lab through the Docker host (192.168.65.1 on
        # Docker Desktop). A request carrying this run's self-mark proves that address is
        # Antigent itself; a wrong mark (or none) proves nothing.
        def run(paths):
            o = FakeObs()
            o._collect_net()
            o.out.clear()
            recs = [{"ts": 5000 + i, "type": "http", "src": "192.168.65.1", "sport": 40000 + i,
                     "dst": "172.19.0.2", "dport": 3000, "method": "GET", "path": p}
                    for i, p in enumerate(paths)]
            recs.append({"ts": 5100, "type": "http", "src": "172.31.0.2", "sport": 41000,
                         "dst": "172.19.0.2", "dport": 3000, "method": "GET",
                         "path": "/whoAmI/api/json"})   # the attacker does not know the mark
            self.write(recs)
            mark = "a" * 32
            with mock.patch.object(gw, "SELF_MARK", mark), \
                    mock.patch.object(gw, "SELF_MARK_RE", gw.re.compile(r"[?&]antigent_self=" + mark + r"(?:&|$)")):
                o._collect_net()
            return o, {e.get("client") for e in o.out if not e.get("internal") and e.get("client")}

        o, seen = run(["/whoAmI/api/json?antigent_self=" + "a" * 32, "/job/x/disable?antigent_self=" + "a" * 32])
        self.assertEqual(o.self_addresses, {"192.168.65.1"})
        self.assertIn("172.31.0.2", seen)
        self.assertNotIn("192.168.65.1", seen)                     # own traffic: no event, no turn
        self.write([])
        o, seen = run(["/whoAmI/api/json?antigent_self=" + "b" * 32, "/whoAmI/api/json"])
        self.assertNotIn("192.168.65.1", o.self_addresses)
        self.assertIn("192.168.65.1", seen)                        # wrong or missing mark: a client

    def test_jenkins_client_adds_the_self_mark_only_when_configured(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scenarios" / "cicd-goat"))
        import adapter
        import urllib.request
        for mark, expect in (("c" * 32, "antigent_self=" + "c" * 32), ("", None)):
            with mock.patch.dict(os.environ, {"ANTIGENT_SELF_MARK": mark}):
                j = adapter.JenkinsHttp("http://jenkins:8080", "u", "p")
            req = urllib.request.Request("http://jenkins:8080/job/a/disable")
            for h in j._opener.handlers:
                fn = getattr(h, "http_request", None)
                if isinstance(h, adapter.SelfMarkHandler):
                    req = fn(req)
            if expect:
                self.assertTrue(req.full_url.endswith("?" + expect))
            else:
                self.assertNotIn("antigent_self", req.full_url)

    def test_target_states_come_from_docker_not_the_network(self):
        o = FakeObs()
        replies = {"gitea": "running healthy", "jenkins-server": "running ", "prod": "exited "}
        calls = []

        def fake_docker(args, timeout=15):
            calls.append(args)
            name = args[-1]
            return (0, replies.get(name, "running "), "") if args[0] == "inspect" else (1, "", "")

        o._docker = fake_docker
        o._states_at = 0.0
        states = {t["name"]: t["up"] for t in o.target_states()}
        self.assertTrue(states["gitea"])
        self.assertTrue(all(c[0] == "inspect" for c in calls))
        self.assertIn(False, states.values())                          # prod exited

    def test_target_joining_a_new_network_is_not_dropped(self):
        # The Attack Box reaches gitea on the lab network, an address the map built at
        # start-up does not have. It must be remapped at once, not dropped as untargeted.
        o = FakeObs()
        o._collect_net()
        # Map built 10 s ago: still within INTERNAL_REFRESH, so the periodic path keeps it.
        o._net_map_at = gw.time.time() - 10
        lab_ip = "172.31.0.4"
        calls = []
        real = o.net_targets

        def remap(force=False):
            calls.append(force)
            if force:   # what a fresh `docker inspect` returns now that gitea joined the lab
                o._net_map = {**o._net_map, lab_ip: "gitea"}
                o._net_map_at = gw.time.time()
                return o._net_map
            return real(force)

        o.net_targets = remap
        self.write([{"ts": 3000, "type": "http", "src": "172.31.0.2", "dst": lab_ip, "dport": 3000,
                     "method": "GET", "path": "/api/v1/repos/search", "status": "200"}])
        o._collect_net()
        self.assertTrue(calls[-1])
        self.assertIn(("gitea", "new-source"), [(e["source"], e["kind"]) for e in o.out])
        self.assertEqual(o.net_stats["untargeted"], 0)

    def test_clean_baseline_filters_only_learned_http_flow(self):
        config = {"duration_sec": 60, "min_count": 3, "min_span_sec": 20,
                  "learn": {"net-http": ["client", "method", "path"]}}
        baseline = CleanBaseline(config, started_at=100)
        for ts in (100, 130, 160):
            baseline.observe({"source": "jenkins", "kind": "net-http", "level": "baseline",
                              "ts": ts, "client": A, "method": "GET", "path": "/health"})
        o = FakeObs()
        o.load_baseline(baseline.finish(160).to_dict())
        o._collect_net()                       # existing history is skipped
        recs = [{"ts": 2000 + i, "type": "http", "src": A, "dst": J, "dport": 8080,
                 "method": "GET", "path": "/health", "status": "200"} for i in range(12)]
        recs += [{"ts": 2100 + i, "type": "http", "src": A, "dst": J, "dport": 8080,
                  "method": "GET", "path": f"/qa/unknown/{i}", "status": "404"} for i in range(10)]
        self.write(recs)
        o._collect_net()
        learned = [e for e in o.out if e["kind"] == "net-http" and e.get("path") == "/health"]
        unknown = [e for e in o.out if e["kind"] == "net-http" and str(e.get("path", "")).startswith("/qa/")]
        self.assertEqual(len(learned), 12)
        self.assertTrue(all(e["level"] == "baseline" for e in learned))
        self.assertEqual(len(unknown), 10)
        self.assertTrue(all(e["level"] == "raw" for e in unknown))
        elevated = {e["kind"] for e in o.out if e["level"] == "elevated"}
        self.assertIn("recon-burst", elevated)
        self.assertIn("error-burst", elevated)

    def test_access_log_role_not_duplicated(self):
        o = FakeObs()
        o._collect_net()
        o._new_source("gitea", "router: completed GET /x for 172.19.0.1:4000, 200 OK", 3000)   # access log names clients
        before = len(o.out)
        self.write([{"ts": 3001 + i, "type": "http", "src": A, "dst": "172.19.0.2", "dport": 3000,
                     "method": "GET", "path": f"/r{i}", "status": "200"} for i in range(12)])
        o._collect_net()
        self.assertEqual(len(o.out), before)              # no duplicate events, no double-counted burst
        self.assertEqual(o.net_stats["dup"], 12)


if __name__ == "__main__":
    unittest.main()
