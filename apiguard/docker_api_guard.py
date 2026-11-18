#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Docker API guard for the defense plane (standard library only).

Replaces a coarse socket proxy. tecnativa/docker-socket-proxy with CONTAINERS=1 + POST=1
allows *every* method under /containers, including POST /containers/create with
Privileged and a host bind mount, i.e. root on the Docker host for anything that can reach
port 2375. This guard allows only what the Antigent gateway, sensor and adapter use:

    GET|HEAD /_ping            GET /version
    GET  /containers/json      (docker ps)
    GET  /containers/<c>/json  (docker inspect)
    GET  /containers/<c>/logs  (docker logs)
    GET  /containers/<c>/changes (docker diff)
    POST /containers/<c>/exec  (docker exec: create)  -- checked, see below
    POST /exec/<id>/start | /exec/<id>/resize, GET /exec/<id>/json

`exec` is refused when the request asks for Privileged, when the target container is
privileged, mounts the Docker socket, has an Antigent-plane name (GUARD_DENY_PREFIXES), is
not in GUARD_EXEC_CONTAINERS / GUARD_EXEC_PROJECTS when those are set, or is this guard.
Each connection carries exactly one checked request (`Connection: close` is forced); only
an upgraded exec stream is relayed in both directions afterwards. Clients must come from
an address of a GUARD_ALLOW_FROM host (default: the `antigent` service).

Environment: GUARD_LISTEN (0.0.0.0:2375), DOCKER_SOCKET (/var/run/docker.sock),
GUARD_ALLOW_FROM ("antigent"; empty = any client on the network), GUARD_DENY_PREFIXES
("antigent-"), GUARD_EXEC_CONTAINERS, GUARD_EXEC_PROJECTS (comma lists; empty = no
allow-list beyond the checks above), GUARD_LOG (JSONL path; stdout always).
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import sys
import time

HEAD_LIMIT = 16384
BODY_LIMIT = 1 << 20
REF = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}"
VERSION = r"(?:/v\d+\.\d+)?"

# (method, path regex, kind). kind "exec-create" gets the container/body checks.
RULES = [
    ({"GET", "HEAD"}, rf"{VERSION}/_ping", None),
    ({"GET"}, rf"{VERSION}/version", None),
    ({"GET"}, rf"{VERSION}/containers/json", None),
    ({"GET"}, rf"{VERSION}/containers/(?P<ref>{REF})/(?:json|logs|changes)", None),
    ({"POST"}, rf"{VERSION}/containers/(?P<ref>{REF})/exec", "exec-create"),
    ({"POST"}, rf"{VERSION}/exec/[A-Fa-f0-9]{{64}}/(?:start|resize)", None),
    ({"GET"}, rf"{VERSION}/exec/[A-Fa-f0-9]{{64}}/json", None),
]
COMPILED = [(m, re.compile(p + r"\Z"), k) for m, p, k in RULES]
HOP_BY_HOP = {"connection", "keep-alive", "proxy-connection", "proxy-authorization", "te",
              "trailer", "upgrade"}


def _split(value: str) -> list[str]:
    return [p.strip() for p in (value or "").split(",") if p.strip()]


def match_rule(method: str, path: str):
    """Return (allowed, kind, ref). The path must be plain: no encoding or traversal."""
    if "%" in path or "//" in path or "/." in path or "\\" in path:
        return False, None, None
    for methods, rx, kind in COMPILED:
        m = rx.match(path)
        if m and method in methods:
            return True, kind, m.groupdict().get("ref")
    return False, None, None


def parse_head(head: bytes):
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        raise ValueError("bad request line")
    method, target, version = parts
    path, _, query = target.partition("?")
    headers = []
    for line in lines[1:]:
        if not line:
            continue
        name, sep, value = line.partition(":")
        if not sep or not name or name != name.strip():
            raise ValueError("bad header")
        headers.append((name, value.strip()))
    return method, path, query, version, headers


class Guard:
    def __init__(self, socket_path="/var/run/docker.sock", allow_from=("antigent",),
                 deny_prefixes=("antigent-",), exec_containers=(), exec_projects=(),
                 log_path=None, self_names=()):
        self.socket_path = socket_path
        self.allow_from = list(allow_from)
        self.deny_prefixes = tuple(deny_prefixes)
        self.exec_containers = set(exec_containers)
        self.exec_projects = set(exec_projects)
        self.log_path = log_path
        self.self_names = {socket.gethostname(), *self_names}
        self._allowed_ips: set[str] = set()
        self._allowed_at = 0.0

    def log(self, **ev):
        line = json.dumps({"ts": round(time.time(), 3), **ev}, ensure_ascii=False)
        print(line, flush=True)
        if self.log_path:
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except OSError:
                pass

    async def client_allowed(self, ip: str) -> bool:
        if not self.allow_from:
            return True
        now = time.time()
        if now - self._allowed_at > 10 or ip not in self._allowed_ips:
            loop = asyncio.get_running_loop()
            ips: set[str] = set()
            for host in self.allow_from:
                try:
                    for info in await loop.getaddrinfo(host, None):
                        ips.add(info[4][0])
                except OSError:
                    continue
            self._allowed_ips, self._allowed_at = ips, now
        return ip in self._allowed_ips

    async def docker_get(self, path: str):
        """One GET to the daemon over the Unix socket; returns (status, json|None)."""
        reader, writer = await asyncio.open_unix_connection(self.socket_path)
        try:
            writer.write(f"GET {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n".encode())
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(), 15)
        finally:
            writer.close()
        head, _, body = raw.partition(b"\r\n\r\n")
        status = int(head.split(b" ", 2)[1])
        if b"transfer-encoding: chunked" in head.lower():
            body = _dechunk(body)
        try:
            return status, json.loads(body or b"null")
        except ValueError:
            return status, None

    async def check_exec(self, ref: str, body: bytes) -> str | None:
        try:
            spec = json.loads(body or b"{}")
        except ValueError:
            return "exec body is not JSON"
        if not isinstance(spec, dict):
            return "exec body is not an object"
        if spec.get("Privileged"):
            return "privileged exec is not allowed"
        status, info = await self.docker_get(f"/containers/{ref}/json")
        if status != 200 or not isinstance(info, dict):
            return f"container lookup failed ({status})"
        name = str(info.get("Name", "")).lstrip("/")
        cid = str(info.get("Id", ""))
        host_cfg = info.get("HostConfig") or {}
        labels = (info.get("Config") or {}).get("Labels") or {}
        if name.startswith(self.deny_prefixes):
            return f"'{name}' is an Antigent plane container"
        if cid[:12] in self.self_names or name in self.self_names:
            return "exec into the API guard is not allowed"
        if host_cfg.get("Privileged"):
            return f"'{name}' is privileged"
        for mount in info.get("Mounts") or []:
            src, dst = str(mount.get("Source", "")), str(mount.get("Destination", ""))
            if "docker.sock" in src or "docker.sock" in dst or dst in ("/var/run", "/run"):
                return f"'{name}' mounts the Docker socket"
        if self.exec_containers or self.exec_projects:
            project = labels.get("com.docker.compose.project", "")
            if name not in self.exec_containers and project not in self.exec_projects:
                return f"'{name}' is not an allow-listed exec target"
        return None

    async def handle(self, reader, writer):
        peer = (writer.get_extra_info("peername") or ("?",))[0]
        try:
            await self._handle(reader, writer, peer)
        except Exception as e:  # noqa: BLE001
            self.log(client=peer, decision="error", reason=repr(e)[:200])
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def _reply(self, writer, code, msg):
        body = json.dumps({"message": f"antigent api guard: {msg}"}).encode()
        writer.write(f"HTTP/1.1 {code} Forbidden\r\nContent-Type: application/json\r\n"
                     f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
        await writer.drain()

    async def _handle(self, reader, writer, peer):
        if not await self.client_allowed(peer):
            self.log(client=peer, decision="deny", reason="client not allowed")
            return await self._reply(writer, 403, "client not allowed")
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
            method, path, query, version, headers = parse_head(head[:-4])
        except Exception:  # noqa: BLE001
            return await self._reply(writer, 400, "bad request")
        allowed, kind, ref = match_rule(method, path)
        if not allowed:
            self.log(client=peer, method=method, path=path, decision="deny", reason="endpoint not allowed")
            return await self._reply(writer, 403, f"{method} {path} is not allowed")
        hmap = {k.lower(): v for k, v in headers}
        if "chunked" in hmap.get("transfer-encoding", "").lower():
            return await self._reply(writer, 411, "chunked request bodies are not accepted")
        try:
            length = int(hmap.get("content-length", "0") or 0)
        except ValueError:
            return await self._reply(writer, 400, "bad content-length")
        if length < 0 or length > BODY_LIMIT:
            return await self._reply(writer, 413, "body too large")
        body = await reader.readexactly(length) if length else b""
        if kind == "exec-create":
            reason = await self.check_exec(ref, body)
            if reason:
                self.log(client=peer, method=method, path=path, decision="deny", reason=reason)
                return await self._reply(writer, 403, reason)
        upgrade = (method == "POST" and path.endswith("/start")
                   and hmap.get("upgrade", "").lower() == "tcp")
        out = [f"{method} {path}{'?' + query if query else ''} {version}"]
        out += [f"{k}: {v}" for k, v in headers if k.lower() not in HOP_BY_HOP]
        out += ["Connection: Upgrade", "Upgrade: tcp"] if upgrade else ["Connection: close"]
        ureader, uwriter = await asyncio.open_unix_connection(self.socket_path)
        uwriter.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1") + body)
        await uwriter.drain()
        self.log(client=peer, method=method, path=path, decision="allow", upgrade=upgrade)

        async def pipe(src, dst):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except (OSError, asyncio.IncompleteReadError):
                pass
            finally:
                try:
                    if dst.can_write_eof():
                        dst.write_eof()
                except (OSError, RuntimeError):
                    pass

        tasks = [pipe(ureader, writer)]
        if upgrade:   # only an upgraded exec stream carries further client bytes (stdin)
            tasks.append(pipe(reader, uwriter))
        await asyncio.gather(*tasks)
        uwriter.close()


def _dechunk(data: bytes) -> bytes:
    out, rest = b"", data
    while rest:
        size_line, _, rest = rest.partition(b"\r\n")
        size = int(size_line.split(b";")[0] or b"0", 16)
        if size == 0:
            break
        out, rest = out + rest[:size], rest[size + 2:]
    return out


async def serve(guard: Guard, listen: str):
    host, _, port = listen.rpartition(":")
    server = await asyncio.start_server(guard.handle, host or "0.0.0.0", int(port), limit=HEAD_LIMIT)
    guard.log(decision="start", listen=listen, allow_from=guard.allow_from,
              exec_containers=sorted(guard.exec_containers), exec_projects=sorted(guard.exec_projects))
    async with server:
        await server.serve_forever()


def main():
    allow_from = os.environ.get("GUARD_ALLOW_FROM", "antigent")
    guard = Guard(
        socket_path=os.environ.get("DOCKER_SOCKET", "/var/run/docker.sock"),
        allow_from=_split(allow_from),
        deny_prefixes=_split(os.environ.get("GUARD_DENY_PREFIXES", "antigent-")) or ("antigent-",),
        exec_containers=_split(os.environ.get("GUARD_EXEC_CONTAINERS", "")),
        exec_projects=_split(os.environ.get("GUARD_EXEC_PROJECTS", "")),
        log_path=os.environ.get("GUARD_LOG") or None,
    )
    if not guard.allow_from:
        print("api-guard: GUARD_ALLOW_FROM is empty; any client on this network is accepted",
              file=sys.stderr)
    asyncio.run(serve(guard, os.environ.get("GUARD_LISTEN", "0.0.0.0:2375")))


if __name__ == "__main__":
    main()
