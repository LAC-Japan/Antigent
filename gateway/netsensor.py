#!/usr/bin/env python3
"""Antigent netsensor (v0.17.0) -- optional network tap for the Docker bridges (NIDS-like).

Why: some target services write no access log (e.g. Jenkins, CTFd), so the log sensors
cannot see who talks to them. netsensor watches the Docker bridge interfaces of the host
and writes one JSON line per HTTP request (with its status) or per non-HTTP TCP connection:

  runs/defense/net/flows.jsonl
    {"ts", "type": "http", "src", "sport", "dst", "dport", "method", "path", "host",
     "user"?, "auth"?, "status"?}
    {"ts", "type": "conn", "src", "sport", "dst", "dport", "proto"}   # tls / ssh / tcp

It knows nothing about the scenario: no ports, no paths, no container names. Mapping a
destination address to a scenario role (and deciding what is internal) is done by the
sensor daemon, which already has the Docker API (netsensor has none).

Privacy: passwords are never written. For HTTP Basic auth only the user name is kept;
other Authorization schemes are reduced to their scheme name; cookies and bodies are not
read; query values whose key looks secret (token, password, key, ...) are masked.

Limits (by design, kept small): one Docker host; IPv4 + TCP; plaintext HTTP only (TLS and
other protocols -> connection records); the request line and headers must be in the first
segment (no TCP reassembly -- true for curl/git/browsers in practice).

Runs as its own container with network_mode: host and CAP_NET_RAW (compose profile
"netsensor"). Standard library only.

  python3 gateway/netsensor.py               # capture loop
Config: NET_OUT (default runs/defense/net/flows.jsonl), NET_IFACES (regex, default
^(docker0|br-.*)$), NET_PROMISC (1), NET_CONN_WAIT (3 s), NET_RESP_WAIT (10 s).
"""
import base64
import json
import os
import re
import select
import socket
import struct
import sys
import time
from pathlib import Path
from urllib.parse import unquote

OUT = Path(os.environ.get("NET_OUT") or
           Path(__file__).resolve().parent.parent / "runs" / "defense" / "net" / "flows.jsonl")
IFACES = re.compile(os.environ.get("NET_IFACES", r"^(docker0|br-.*)$"))
PROMISC = os.environ.get("NET_PROMISC", "1") != "0"
CONN_WAIT = float(os.environ.get("NET_CONN_WAIT", "3"))
RESP_WAIT = float(os.environ.get("NET_RESP_WAIT", "10"))
IFACE_REFRESH = 10.0
MAX_FLOWS = 20000

METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ",
           b"PROPFIND ", b"CONNECT ", b"TRACE ")
SECRET_KEY = re.compile(r"(?i)(pass|pwd|token|secret|key|auth|sig|session|cred|code)")

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1


def log(*a):
    print("[netsensor]", *a, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# Parsing (pure functions; unit-tested)
# --------------------------------------------------------------------------- #
def parse_frame(frame: bytes) -> dict | None:
    """Ethernet frame -> {src, dst, sport, dport, syn, ack, fin, rst, payload} for IPv4/TCP."""
    if len(frame) < 14:
        return None
    off = 12
    etype = struct.unpack_from("!H", frame, off)[0]
    while etype in (0x8100, 0x88A8) and len(frame) >= off + 6:   # VLAN tags
        off += 4
        etype = struct.unpack_from("!H", frame, off)[0]
    off += 2
    if etype != 0x0800 or len(frame) < off + 20:
        return None
    ihl = (frame[off] & 0x0F) * 4
    if frame[off + 9] != 6 or ihl < 20:
        return None
    total = struct.unpack_from("!H", frame, off + 2)[0]
    src = socket.inet_ntoa(frame[off + 12:off + 16])
    dst = socket.inet_ntoa(frame[off + 16:off + 20])
    t = off + ihl
    if len(frame) < t + 20:
        return None
    sport, dport, seq = struct.unpack_from("!HHI", frame, t)
    doff = (frame[t + 12] >> 4) * 4
    flags = frame[t + 13]
    end = min(len(frame), off + total) if total else len(frame)
    return {"src": src, "dst": dst, "sport": sport, "dport": dport, "seq": seq,
            "syn": bool(flags & 0x02), "ack": bool(flags & 0x10),
            "fin": bool(flags & 0x01), "rst": bool(flags & 0x04),
            "payload": frame[t + doff:end]}


def mask_path(path: str) -> str:
    """Mask query values whose key looks secret; keep everything else."""
    base, q, query = path.partition("?")
    if not q:
        return path[:500]
    parts = []
    for kv in query.split("&"):
        k, eq, v = kv.partition("=")
        parts.append(f"{k}=***" if eq and SECRET_KEY.search(unquote(k)) else kv)
    return (base + "?" + "&".join(parts))[:500]


def parse_request(payload: bytes) -> dict | None:
    """First segment of an HTTP/1.x request -> {method, path, host, user?, auth?}."""
    if not payload.startswith(METHODS):
        return None
    head = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    lines = head.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) < 3 or not parts[2].startswith("HTTP/"):
        return None
    req = {"method": parts[0], "path": mask_path(parts[1])}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        name, value = name.strip().lower(), value.strip()
        if name == "host":
            req["host"] = value[:200]
        elif name == "authorization":
            scheme, _, cred = value.partition(" ")
            if scheme.lower() == "basic":
                try:
                    user = base64.b64decode(cred.strip(), validate=False).decode("utf-8", "replace")
                    req["user"] = user.partition(":")[0][:100]   # the password is dropped here
                except (ValueError, UnicodeError):
                    req["auth"] = "basic"
            else:
                req["auth"] = scheme.lower()[:20]
    return req


def parse_status(payload: bytes) -> str | None:
    m = re.match(rb"HTTP/\d(?:\.\d)? (\d{3})", payload[:16])
    return m.group(1).decode() if m else None


class Tracker:
    """TCP flow state: pairs HTTP requests with responses, and reports non-HTTP connections.

    feed(pkt, t) / tick(t) return the records to write."""

    def __init__(self, conn_wait=CONN_WAIT, resp_wait=RESP_WAIT):
        self.conn_wait = conn_wait
        self.resp_wait = resp_wait
        self.syn: dict[tuple, dict] = {}       # client flow -> {t, proto?}
        self.http: dict[tuple, list] = {}      # client flow -> [request records awaiting status]
        self.recent: dict[tuple, float] = {}   # same segment seen twice (loopback, retransmit)

    def feed(self, p: dict, t: float) -> list[dict]:
        out = []
        flow = (p["src"], p["sport"], p["dst"], p["dport"])
        seg = (flow, p.get("seq"), len(p["payload"]), p["syn"], p["ack"], p["rst"], p["fin"])
        if seg in self.recent and t - self.recent[seg] < 2.0:
            return out
        self.recent[seg] = t
        if len(self.recent) > 4096:
            self.recent = {k: v for k, v in self.recent.items() if t - v < 2.0}
        back = (p["dst"], p["dport"], p["src"], p["sport"])
        if p["syn"] and not p["ack"]:
            if flow not in self.syn and len(self.syn) < MAX_FLOWS:
                self.syn[flow] = {"t": t}
            return out
        pl = p["payload"]
        if not pl:
            if p["rst"] and back in self.syn:   # refused: report now (port scans)
                out.append(self._conn(back, self.syn.pop(back), t, "refused"))
            return out
        req = parse_request(pl)
        if req:
            self.syn.pop(flow, None)            # an HTTP flow: the request is the record
            rec = {"ts": round(t, 3), "type": "http", "src": p["src"], "sport": p["sport"],
                   "dst": p["dst"], "dport": p["dport"], **req}
            if len(self.http) < MAX_FLOWS:
                self.http.setdefault(flow, []).append(rec)
            else:
                out.append(rec)
            return out
        status = parse_status(pl)
        if status and self.http.get(back):
            rec = self.http[back].pop(0)
            if not self.http[back]:
                del self.http[back]
            rec["status"] = status
            out.append(rec)
            return out
        if flow in self.syn:                    # client spoke first, not HTTP
            out.append(self._conn(flow, self.syn.pop(flow), t, "tls" if pl[:1] == b"\x16" else "tcp"))
        elif back in self.syn:                  # server spoke first (banner)
            out.append(self._conn(back, self.syn.pop(back), t, "ssh" if pl.startswith(b"SSH-") else "tcp"))
        return out

    @staticmethod
    def _conn(flow, st, t, proto):
        return {"ts": round(st["t"], 3), "type": "conn", "src": flow[0], "sport": flow[1],
                "dst": flow[2], "dport": flow[3], "proto": proto}

    def tick(self, t: float) -> list[dict]:
        out = []
        for flow, st in list(self.syn.items()):
            if t - st["t"] >= self.conn_wait:
                out.append(self._conn(flow, self.syn.pop(flow), t, "tcp"))
        for flow, reqs in list(self.http.items()):
            while reqs and t - reqs[0]["ts"] >= self.resp_wait:
                out.append(reqs.pop(0))         # no status seen (pipelined / lost / long poll)
            if not reqs:
                del self.http[flow]
        return out


# --------------------------------------------------------------------------- #
# Capture loop
# --------------------------------------------------------------------------- #
def open_iface(name: str):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((name, 0))
    s.setblocking(False)
    if PROMISC:   # bridge in promiscuous mode also hands up container-to-container frames
        try:
            idx = socket.if_nametoindex(name)
            s.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, struct.pack("iHH8s", idx, PACKET_MR_PROMISC, 0, b""))
        except OSError as e:
            log(f"{name}: promiscuous mode unavailable ({e}); host<->container traffic only")
    return s


def main():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    out = open(OUT, "a", encoding="utf-8", buffering=1)
    socks: dict[str, socket.socket] = {}
    tracker = Tracker()
    last_refresh = 0.0
    log(f"writing {OUT}; interfaces matching {IFACES.pattern}")
    while True:
        now = time.time()
        if now - last_refresh >= IFACE_REFRESH:
            last_refresh = now
            try:
                names = {n for n in os.listdir("/sys/class/net") if IFACES.match(n)}
            except OSError:
                names = set()
            for n in names - socks.keys():
                try:
                    socks[n] = open_iface(n)
                    log(f"capturing on {n}")
                except OSError as e:
                    log(f"cannot capture on {n}: {e} (needs network_mode: host and CAP_NET_RAW)")
            for n in set(socks) - names:
                socks.pop(n).close()
                log(f"interface gone: {n}")
            if not socks:
                log("no matching interfaces yet")
        ready = select.select(list(socks.values()), [], [], 1.0)[0] if socks else (time.sleep(1) or [])
        recs = []
        for s in ready:
            for _ in range(256):
                try:
                    frame, addr = s.recvfrom(65535)
                except (BlockingIOError, InterruptedError):
                    break
                except OSError:
                    break
                p = parse_frame(frame)
                if p:
                    recs += tracker.feed(p, time.time())
        recs += tracker.tick(time.time())
        for r in recs:
            out.write(json.dumps(r, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
