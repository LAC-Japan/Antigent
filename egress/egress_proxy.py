#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Allowlist egress proxy for the Attack Box (standard library only).

The Attack Box sits on an *internal* Docker network with no host address, so it has no
route to the Internet, the Docker host, or cloud metadata, and no external DNS. The only
way out is this proxy, which accepts nothing but

    CONNECT <allow-listed host>:<allowed port> HTTP/1.1

i.e. TLS tunnels to the configured LLM API hosts. Plain-HTTP proxying, IP literals,
unlisted hosts, other ports, and names that resolve to non-public addresses are refused.
The proxy connects to the address it vetted (no second DNS lookup), so a rebinding answer
cannot redirect an approved name to the host or to metadata endpoints.

Configuration (environment):
  EGRESS_ALLOW          comma list; "api.openai.com", ".amazonaws.com" (suffix),
                        "llm.lab:8001" (host with an explicit extra port)
  EGRESS_ALLOW_PRIVATE  comma list of allow-listed hosts that MAY resolve to private
                        addresses (a self-hosted LLM endpoint); empty by default
  EGRESS_PORTS          default ports for entries without one (default "443")
  EGRESS_LISTEN         host:port (default 0.0.0.0:3128)
  EGRESS_LOG            JSONL decision log (default: stdout only)
  EGRESS_MAX_CONN       concurrent tunnels (default 64)
  EGRESS_IDLE_SEC       idle timeout per tunnel (default 900, LLM streams can be slow)
  EGRESS_UPSTREAM_PROXY optional http://[user:pass@]host:port of a corporate proxy; allowed
                        tunnels are then opened through it (the allowlist still applies)
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import os
import socket
import sys
import time
from urllib.parse import unquote, urlsplit

HEAD_LIMIT = 8192
HEAD_TIMEOUT = 10.0


def _split(value: str) -> list[str]:
    return [p.strip().lower() for p in (value or "").split(",") if p.strip()]


class Policy:
    def __init__(self, allow: str, allow_private: str = "", ports: str = "443"):
        self.default_ports = {int(p) for p in _split(ports)} or {443}
        self.exact: dict[str, set[int]] = {}
        self.suffix: dict[str, set[int]] = {}
        for entry in _split(allow):
            host, _, port = entry.rpartition(":") if entry.count(":") == 1 else (entry, "", "")
            host = host or entry
            ports_for = {int(port)} if port.isdigit() else set(self.default_ports)
            table = self.suffix if host.startswith(".") else self.exact
            table.setdefault(host.rstrip("."), set()).update(ports_for)
        self.allow_private = {h.rstrip(".") for h in _split(allow_private)}

    def match(self, host: str, port: int) -> str | None:
        """Return a refusal reason, or None when host:port is allowed."""
        host = host.lower().rstrip(".")
        try:
            ipaddress.ip_address(host.strip("[]"))
            return "ip-literal"
        except ValueError:
            pass
        if not host or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in host):
            return "bad-host"
        ports = self.exact.get(host)
        if ports is None:
            for suf, sp in self.suffix.items():
                if host.endswith(suf) and len(host) > len(suf):
                    ports = sp
                    break
        if ports is None:
            return "host-not-allowed"
        if port not in ports:
            return "port-not-allowed"
        return None


def public_address(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def parse_connect(head: bytes) -> tuple[str, int]:
    line = head.split(b"\r\n", 1)[0].decode("latin-1")
    parts = line.split(" ")
    if len(parts) != 3 or parts[0] != "CONNECT" or not parts[2].startswith("HTTP/1."):
        raise ValueError("only CONNECT is allowed")
    target = parts[1]
    if target.startswith("["):
        host, _, rest = target[1:].partition("]")
        port = rest.lstrip(":")
    else:
        host, _, port = target.rpartition(":")
    if not host or not port.isdigit() or not (0 < int(port) < 65536):
        raise ValueError("bad CONNECT target")
    return host, int(port)


def parse_upstream(url: str):
    """http://[user:pass@]host:port -> (host, port, Proxy-Authorization value or None)."""
    if not url:
        return None
    u = urlsplit(url if "://" in url else "http://" + url)
    if u.scheme != "http" or not u.hostname:
        raise ValueError("EGRESS_UPSTREAM_PROXY must be http://host:port")
    auth = None
    if u.username:
        raw = f"{unquote(u.username)}:{unquote(u.password or '')}".encode()
        auth = "Basic " + base64.b64encode(raw).decode()
    return u.hostname, u.port or 8080, auth


class EgressProxy:
    def __init__(self, policy: Policy, log_path: str | None = None, max_conn: int = 64,
                 idle: float = 900.0, resolver=None, upstream=None):
        self.upstream = upstream
        self.policy = policy
        self.log_path = log_path
        self.sem = asyncio.Semaphore(max_conn)
        self.idle = idle
        self.resolver = resolver or self._resolve

    @staticmethod
    async def _resolve(host: str, port: int) -> list[str]:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return list(dict.fromkeys(i[4][0] for i in infos))

    def log(self, **ev):
        ev = {"ts": round(time.time(), 3), **ev}
        line = json.dumps(ev, ensure_ascii=False)
        print(line, flush=True)
        if self.log_path:
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except OSError:
                pass

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = (writer.get_extra_info("peername") or ("?",))[0]
        async with self.sem:
            try:
                await self._handle(reader, writer, peer)
            except Exception as e:  # noqa: BLE001
                self.log(client=peer, decision="error", reason=repr(e)[:200])
            finally:
                try:
                    writer.close()
                except Exception:  # noqa: BLE001
                    pass

    @staticmethod
    async def _direct(addrs, port):
        for addr in addrs:
            try:
                return await asyncio.wait_for(asyncio.open_connection(addr, port), 15)
            except (OSError, asyncio.TimeoutError):
                continue
        return None

    async def _via_upstream(self, host, port):
        uhost, uport, auth = self.upstream
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(uhost, uport), 15)
            req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            if auth:
                req += f"Proxy-Authorization: {auth}\r\n"
            w.write((req + "\r\n").encode())
            await w.drain()
            head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 20)
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            return None
        status = head.split(b"\r\n", 1)[0].split(b" ")
        if len(status) < 2 or status[1] != b"200":
            w.close()
            return None
        return r, w

    async def _deny(self, writer, peer, code, reason, host=None, port=None):
        self.log(client=peer, host=host, port=port, decision="deny", reason=reason)
        body = f"egress denied: {reason}\n".encode()
        writer.write(f"HTTP/1.1 {code} Forbidden\r\nContent-Type: text/plain\r\n"
                     f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
        await writer.drain()

    async def _handle(self, reader, writer, peer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
            return await self._deny(writer, peer, 400, "bad-request")
        try:
            host, port = parse_connect(head)
        except ValueError as e:
            first = head.split(b"\r\n", 1)[0][:200].decode("latin-1", "replace")
            self.log(client=peer, request=first, decision="deny", reason=str(e))
            body = b"egress denied: only HTTPS CONNECT to allow-listed LLM API hosts\n"
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: "
                         + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            await writer.drain()
            return
        reason = self.policy.match(host, port)
        if reason:
            return await self._deny(writer, peer, 403, reason, host, port)
        try:
            addrs = await asyncio.wait_for(self.resolver(host, port), HEAD_TIMEOUT)
        except Exception:  # noqa: BLE001
            addrs = None
            if not self.upstream:   # through an upstream proxy, it resolves the name itself
                return await self._deny(writer, peer, 502, "dns-failure", host, port)
        private_ok = host.lower().rstrip(".") in self.policy.allow_private
        if addrs is not None and (not addrs or (not private_ok and not all(public_address(a) for a in addrs))):
            return await self._deny(writer, peer, 403, "non-public-address", host, port)
        up = await (self._via_upstream(host, port) if self.upstream else self._direct(addrs, port))
        if up is None:
            return await self._deny(writer, peer, 502, "connect-failed", host, port)
        ureader, uwriter = up
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        # Logged when the tunnel opens: an LLM client keeps one tunnel open for the whole
        # session, so an entry written only at close would hide that the API was reached.
        self.log(client=peer, host=host, port=port, decision="allow")
        t0 = time.time()
        counts = {"up": 0, "down": 0}

        async def pipe(src, dst, key):
            try:
                while True:
                    data = await asyncio.wait_for(src.read(65536), self.idle)
                    if not data:
                        break
                    counts[key] += len(data)
                    dst.write(data)
                    await dst.drain()
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
                pass
            finally:
                try:
                    dst.close()
                except Exception:  # noqa: BLE001
                    pass

        await asyncio.gather(pipe(reader, uwriter, "up"), pipe(ureader, writer, "down"))
        self.log(client=peer, host=host, port=port, decision="close", bytes_up=counts["up"],
                 bytes_down=counts["down"], duration=round(time.time() - t0, 3))


async def serve(proxy: EgressProxy, listen: str):
    host, _, port = listen.rpartition(":")
    server = await asyncio.start_server(proxy.handle, host or "0.0.0.0", int(port), limit=HEAD_LIMIT)
    proxy.log(decision="start", listen=listen, allow=sorted(proxy.policy.exact) + sorted(proxy.policy.suffix))
    async with server:
        await server.serve_forever()


def main():
    allow = os.environ.get("EGRESS_ALLOW", "")
    if not _split(allow):
        print("egress-proxy: EGRESS_ALLOW is empty; every request will be refused", file=sys.stderr)
    policy = Policy(allow, os.environ.get("EGRESS_ALLOW_PRIVATE", ""), os.environ.get("EGRESS_PORTS", "443"))
    proxy = EgressProxy(policy, os.environ.get("EGRESS_LOG") or None,
                        int(os.environ.get("EGRESS_MAX_CONN", "64")),
                        float(os.environ.get("EGRESS_IDLE_SEC", "900")),
                        upstream=parse_upstream(os.environ.get("EGRESS_UPSTREAM_PROXY", "")))
    asyncio.run(serve(proxy, os.environ.get("EGRESS_LISTEN", "0.0.0.0:3128")))


if __name__ == "__main__":
    main()
