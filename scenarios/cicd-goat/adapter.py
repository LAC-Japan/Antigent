"""Target-native, recoverable operations for the bounded CI/CD Goat adapter.

Only two operations are supported: create a previously absent repository file and
disable one exact Jenkins WorkflowJob.  Both snapshot native state, apply narrowly,
and independently read the target back.  Raw content and credentials are never put
in receipts.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.cookiejar
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

SCHEMA_DELIVERY = "delivery_observation_v1"
SCHEMA_CONTAINMENT = "containment_observation_v1"
SCHEMA_EFFECT = "side_effect_v1"
SCHEMA_RECOVERY = "recovery_v1"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def evidence_id(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _valid_component(value: Any) -> bool:
    return bool(
        isinstance(value, str) and value not in {".", ".."}
        and re.fullmatch(r"[A-Za-z0-9_.-]+", value)
    )


def _valid_repository(value: Any) -> bool:
    if not isinstance(value, str) or value.count("/") != 1 or value.endswith(".git"):
        return False
    owner, repo = value.split("/")
    return _valid_component(owner) and _valid_component(repo)


def _valid_ref(value: Any) -> bool:
    return bool(
        isinstance(value, str) and 0 < len(value) <= 100
        and re.fullmatch(r"[A-Za-z0-9._/-]+", value)
        and not value.startswith(("/", "-")) and not value.endswith(("/", ".lock"))
        and ".." not in value and "@{" not in value and "//" not in value
    )


def _valid_path(value: Any) -> bool:
    return bool(
        isinstance(value, str) and 0 < len(value) <= 200
        and re.fullmatch(r"[A-Za-z0-9._/-]+", value)
        and not value.startswith("/") and ".." not in value.split("/")
        and "//" not in value and not value.endswith("/")
    )


def _valid_job(value: Any) -> bool:
    return bool(
        isinstance(value, str) and 0 < len(value) <= 300
        and all(part and part not in {".", ".."} for part in value.split("/"))
        and not any(ord(char) < 32 for char in value)
    )


class SelfMarkHandler(urllib.request.BaseHandler):
    """Appends the run's self-mark query parameter (ANTIGENT_SELF_MARK, see the gateway) to every
    request, so the sensors recognise Antigent's own Jenkins traffic instead of treating its
    source address (the Docker host, on Docker Desktop) as a new client."""

    def __init__(self, mark: str):
        self.mark = mark

    def _mark(self, request):
        sep = "&" if "?" in request.full_url else "?"
        request.full_url = request.full_url + sep + urllib.parse.urlencode({SELF_MARK_PARAM: self.mark})
        return request

    http_request = https_request = _mark


SELF_MARK_PARAM = "antigent_self"


class JenkinsHttp:
    """Small standard-library Jenkins API client used inside the defense container."""

    def __init__(self, base_url: str, user: str, password: str, timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self._headers = {"Authorization": f"Basic {token}", "Cache-Control": "no-cache"}
        # The lab's Jenkins is reached directly. An empty ProxyHandler ignores HTTP(S)_PROXY in the
        # container environment (e.g. a corporate proxy injected by Docker Desktop), which cannot
        # reach host.docker.internal or the lab network.
        handlers = [urllib.request.ProxyHandler({}),
                    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())]
        mark = os.environ.get("ANTIGENT_SELF_MARK", "").strip()
        if mark:
            handlers.append(SelfMarkHandler(mark))
        self._opener = urllib.request.build_opener(*handlers)

    def _job_url(self, job_full_name: str, suffix: str = "") -> str:
        path = "/job/" + "/job/".join(urllib.parse.quote(part, safe="") for part in job_full_name.split("/"))
        return self.base_url + path + suffix

    def _request(self, request: urllib.request.Request) -> dict:
        with self._opener.open(request, timeout=self.timeout) as response:  # noqa: S310 -- fixed lab URL
            body = response.read()
        return json.loads(body or b"{}")

    def _config_disabled(self, job_full_name: str) -> bool | None:
        request = urllib.request.Request(
            self._job_url(job_full_name, "/config.xml"), headers=self._headers
        )
        with self._opener.open(request, timeout=self.timeout) as response:  # noqa: S310 -- fixed lab URL
            text = response.read(2_000_000).decode("utf-8", errors="replace")
        match = re.search(r"<disabled>\s*(true|false)\s*</disabled>", text)
        return match.group(1) == "true" if match else None

    def _crumb(self) -> dict[str, str]:
        request = urllib.request.Request(self.base_url + "/crumbIssuer/api/json", headers=self._headers)
        data = self._request(request)
        return {data["crumbRequestField"]: data["crumb"]}

    def job_state(self, job_full_name: str) -> dict:
        if not _valid_job(job_full_name):
            raise ValueError("invalid Jenkins job full name")
        tree = "fullName,_class,disabled,builds[number,timestamp,building]{0,100}"
        url = self._job_url(job_full_name, "/api/json?" + urllib.parse.urlencode({"tree": tree}))
        data = self._request(urllib.request.Request(url, headers=self._headers))
        if data.get("_class") == "org.jenkinsci.plugins.workflow.job.WorkflowJob" and not isinstance(
            data.get("disabled"), bool
        ):
            data["disabled"] = self._config_disabled(job_full_name)
        return data

    def set_job_disabled(self, job_full_name: str, disabled: bool) -> None:
        if not _valid_job(job_full_name):
            raise ValueError("invalid Jenkins job full name")
        endpoint = "/disable" if disabled else "/enable"
        try:
            request = urllib.request.Request(
                self._job_url(job_full_name, endpoint), data=b"", method="POST",
                headers={**self._headers, **self._crumb()},
            )
            with self._opener.open(request, timeout=self.timeout) as response:  # noqa: S310 -- fixed lab URL
                response.read()
        except urllib.error.HTTPError as exc:
            if exc.code not in {403, 404}:
                raise
            script = (
                "import jenkins.model.Jenkins\n"
                f"def item = Jenkins.instance.getItemByFullName({json.dumps(job_full_name)})\n"
                "if (item == null) { throw new IllegalArgumentException('job not found') }\n"
                f"item.setDisabled({str(disabled).lower()})\n"
                "item.save()\n"
            )
            request = urllib.request.Request(
                self.base_url + "/scriptText", method="POST",
                data=urllib.parse.urlencode({"script": script}).encode(),
                headers={**self._headers, **self._crumb(), "Content-Type": "application/x-www-form-urlencoded"},
            )
            with self._opener.open(request, timeout=self.timeout) as response:  # noqa: S310 -- fixed lab URL
                response.read()


def jenkins_error(exc: BaseException) -> str:
    """Short, credential-free reason for a failed Jenkins request (shown to the operator and the
    agent): HTTP status, or the network error, without URLs, headers or response bodies."""
    if isinstance(exc, urllib.error.HTTPError):
        hint = {401: " (wrong user or password)", 403: " (user lacks permission)",
                404: " (no such job)"}.get(exc.code, "")
        return f"HTTP {exc.code}{hint}"
    if isinstance(exc, urllib.error.URLError):
        return f"cannot reach Jenkins ({type(exc.reason).__name__}: {str(exc.reason)[:80]})"
    return f"{type(exc).__name__}: {str(exc)[:80]}"


def _build_watermark(builds: Any) -> list[dict]:
    result = []
    for build in (builds or [])[:100]:
        if not isinstance(build, dict) or not isinstance(build.get("number"), int):
            continue
        result.append({
            "number": build["number"],
            "timestamp": int(build.get("timestamp") or 0),
            "building": bool(build.get("building")),
        })
    return result


def _is_workflow_job(state: dict, full_name: str) -> bool:
    return (state.get("fullName") == full_name
            and state.get("_class") == "org.jenkinsci.plugins.workflow.job.WorkflowJob"
            and isinstance(state.get("disabled"), bool)
            and isinstance(state.get("builds"), list))


class CicdGoatAdapter:
    def __init__(
        self,
        *,
        docker: str = "docker",
        gitea_container: str = "gitea",
        jenkins: Any = None,
        exec_fn: Callable[..., Any] | None = None,
    ):
        self.docker = docker
        self.gitea_container = gitea_container
        self.jenkins = jenkins
        self.exec_fn = exec_fn or self._exec

    def _exec(self, argv: list[str], timeout: int = 60) -> Any:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)

    @staticmethod
    def _base(role: str, command: str) -> dict:
        return {
            "role": role, "label": "exec", "command": command, "marker": "",
            "stdout": "", "stderr": "", "exit_code": 1, "duration": 0.0,
            "status": "done", "observations": [], "effect": None,
        }

    def execute(self, action: dict, action_id: str) -> dict:
        operation = action.get("operation")
        if operation == "gitea_repo_file":
            return self._apply_gitea(action, action_id)
        if operation == "jenkins_disable_job":
            return self._apply_jenkins(action, action_id)
        result = self._base(str(action.get("role") or ""), "typed operation required")
        result["label"] = "refused"
        result["status"] = "refused"
        result["exit_code"] = None
        result["stderr"] = "bounded protocol supports only gitea_repo_file and jenkins_disable_job"
        return result

    def _docker_git(
        self, script: str, *, env: dict[str, str] | None = None, user: str = "git"
    ) -> Any:
        argv = [self.docker, "exec", "-u", user]
        for key, value in sorted((env or {}).items()):
            argv += ["-e", f"{key}={value}"]
        argv += [self.gitea_container, "sh", "-c", script]
        return self.exec_fn(argv, timeout=60)

    @staticmethod
    def _key_values(text: str) -> dict[str, str]:
        result = {}
        for line in (text or "").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                if re.fullmatch(r"[a-z_]+", key):
                    result[key] = value
        return result

    def _gitea_ref(self, repository: str, ref: str) -> str | None:
        script = (
            'bare="/data/git/repositories/$ANTIGENT_REPOSITORY.git"; '
            'git --git-dir="$bare" rev-parse --verify "refs/heads/$ANTIGENT_REF" 2>/dev/null || true'
        )
        proc = self._docker_git(script, env={"ANTIGENT_REPOSITORY": repository, "ANTIGENT_REF": ref})
        value = (proc.stdout or "").strip()
        return value if proc.returncode == 0 and re.fullmatch(r"[0-9a-f]{40,64}", value) else None

    def _canonical_gitea_repository(self, repository: str) -> str | None:
        """Resolve observed casing to one native bare repository without guessing."""
        if not _valid_repository(repository):
            return None
        proc = self._docker_git(
            'root=/data/git/repositories; '
            'find "$root" -mindepth 2 -maxdepth 2 -type d -name "*.git" -print 2>/dev/null'
        )
        if proc.returncode != 0:
            return None
        prefix = "/data/git/repositories/"
        matches = set()
        for line in (proc.stdout or "").splitlines():
            if not line.startswith(prefix) or not line.endswith(".git"):
                continue
            candidate = line[len(prefix):-4]
            if _valid_repository(candidate) and candidate.casefold() == repository.casefold():
                matches.add(candidate)
        return matches.pop() if len(matches) == 1 else None

    def _gitea_push_identity(self) -> tuple[str, str] | None:
        """Return an existing administrator for Gitea's authenticated hook path."""
        try:
            proc = self._docker_git("gitea admin user list --admin")
        except Exception:
            return None
        if proc.returncode != 0:
            return None
        for line in (proc.stdout or "").splitlines():
            fields = line.split()
            if len(fields) >= 2 and re.fullmatch(r"[0-9]+", fields[0]):
                return fields[0], fields[1]
        return None

    def _apply_gitea(self, action: dict, action_id: str) -> dict:
        started = time.time()
        repository, ref, path = action.get("repository"), action.get("ref"), action.get("path")
        content = action.get("content")
        marker = str(action.get("marker") or "")
        source_events = action.get("evidence")
        locator = {"repository": repository, "ref": ref, "path": path}
        result = self._base(
            "gitea", f"[gitea] operation=gitea_repo_file locator_sha256={_sha256_text(json.dumps(locator, sort_keys=True))}"
        )

        def fail_before_apply(message: str, code: int = 1) -> dict:
            current = None
            if _valid_repository(repository) and _valid_ref(ref):
                try:
                    current = self._gitea_ref(repository, ref)
                except Exception:
                    current = None
            delivery = {
                "schema_version": SCHEMA_DELIVERY, "record_type": "delivery_observation",
                "action_id": action_id, "execution_exit_code": code, "surface": "gitea_repo_file",
                "required": True, "locator_sha256": evidence_id(locator),
                "content_sha256": _sha256_text(content) if isinstance(content, str) else None,
                "marker_sha256": _sha256_text(marker), "native_object_id": None,
                "observed_head": current,
                "source_event_indexes": source_events if isinstance(source_events, list) else [],
                "principal_verification": "not_evaluated", "visible_at": None,
                "verified_at": time.time(), "status": "not_delivered",
                "verification_method": "gitea_bare_ref_and_content_readback",
            }
            delivery["evidence_id"] = evidence_id(delivery)
            effect = {
                "schema_version": SCHEMA_EFFECT, "action_id": action_id,
                "operation": "gitea_repo_file",
                "target": {"repository": repository, "ref": ref, "path": path},
                "before": {"commit": None}, "after": {"commit": None, "observed_head": current},
                "cleanup_required": False, "attribution": "defense",
            }
            effect["effect_id"] = evidence_id(effect)
            result.update({
                "exit_code": code, "duration": round(time.time() - started, 3),
                "stderr": message,
                "observations": [{"type": "delivery_observation", "observation": delivery}],
                "effect": effect,
            })
            return result

        # One refusal reason per check, so a failed attempt says what to fix.
        problems = [
            (not _valid_repository(repository), "repository must be owner/repo"),
            (not _valid_ref(ref), "invalid ref"),
            (not _valid_path(path), "invalid relative path"),
            (not (isinstance(content, str) and 0 < len(content) <= 8192 and "\x00" not in content),
             "content must be non-empty text up to 8192 characters"),
            (not marker, "marker is required"),
            (bool(marker) and isinstance(content, str) and marker not in content,
             "marker must appear in content"),
            (not re.fullmatch(r"[0-9a-f]{10}", action_id), "invalid action id"),
            (not (isinstance(source_events, list) and source_events
                  and all(isinstance(index, int) and index > 0 for index in source_events)),
             "evidence must list observed event indexes"),
        ]
        reasons = [text for failed, text in problems if failed]
        if reasons:
            return fail_before_apply("invalid gitea_repo_file operation: " + "; ".join(reasons), 2)
        try:
            canonical_repository = self._canonical_gitea_repository(repository)
        except Exception:
            canonical_repository = None
        if canonical_repository is None:
            return fail_before_apply("gitea native repository identity was not uniquely resolved", 2)
        repository = canonical_repository
        locator = {"repository": repository, "ref": ref, "path": path}
        result["command"] = (
            f"[gitea] operation=gitea_repo_file locator_sha256={_sha256_text(json.dumps(locator, sort_keys=True))}"
        )
        snapshot_script = (
            'set -eu; bare="/data/git/repositories/$ANTIGENT_REPOSITORY.git"; '
            'before=$(git --git-dir="$bare" rev-parse --verify "refs/heads/$ANTIGENT_REF"); '
            'if git --git-dir="$bare" cat-file -e "$before:$ANTIGENT_PATH" 2>/dev/null; then exit 41; fi; '
            'printf "before=%s\\n" "$before"'
        )
        try:
            snapshot = self._docker_git(snapshot_script, env={
                "ANTIGENT_REPOSITORY": repository, "ANTIGENT_REF": ref, "ANTIGENT_PATH": path,
            })
        except Exception:
            return fail_before_apply("gitea snapshot failed")
        if snapshot.returncode != 0:
            return fail_before_apply("gitea snapshot rejected a missing ref or existing path", snapshot.returncode)
        before = self._key_values(snapshot.stdout).get("before")
        if not before or not re.fullmatch(r"[0-9a-f]{40,64}", before):
            return fail_before_apply("gitea snapshot returned no native commit")
        apply_script = (
            'set -eu; bare="/data/git/repositories/$ANTIGENT_REPOSITORY.git"; '
            'current=$(git --git-dir="$bare" rev-parse "refs/heads/$ANTIGENT_REF"); '
            'test "$current" = "$ANTIGENT_BEFORE"; '
            'index=$(mktemp); trap \'find "$index" -delete\' EXIT; export GIT_INDEX_FILE="$index"; '
            'git --git-dir="$bare" read-tree "$ANTIGENT_BEFORE"; '
            'blob=$(printf %s "$ANTIGENT_CONTENT" | git --git-dir="$bare" hash-object -w --stdin); '
            'git --git-dir="$bare" update-index --add --cacheinfo "100644,$blob,$ANTIGENT_PATH"; '
            'tree=$(git --git-dir="$bare" write-tree); '
            'export GIT_AUTHOR_NAME="CI Bot" GIT_AUTHOR_EMAIL="ci@wonderland.local" '
            'GIT_COMMITTER_NAME="CI Bot" GIT_COMMITTER_EMAIL="ci@wonderland.local"; '
            'commit=$(git --git-dir="$bare" commit-tree "$tree" -p "$ANTIGENT_BEFORE" -m "add CI environment config"); '
            'git --git-dir="$bare" push --quiet "$bare" "$commit:refs/heads/$ANTIGENT_REF"; '
            'printf "after=%s\\n" "$commit"'
        )
        applied = None
        identity = self._gitea_push_identity()
        if identity is None:
            return fail_before_apply("gitea hook identity discovery failed")
        pusher_id, pusher_name = identity
        owner, repo_name = repository.split("/")
        try:
            applied = self._docker_git(apply_script, env={
                "ANTIGENT_REPOSITORY": repository, "ANTIGENT_REF": ref, "ANTIGENT_PATH": path,
                "ANTIGENT_CONTENT": content, "ANTIGENT_BEFORE": before,
                "GITEA_REPO_USER_NAME": owner, "GITEA_REPO_NAME": repo_name,
                "GITEA_REPO_IS_WIKI": "false", "GITEA_PUSHER_ID": pusher_id,
                "GITEA_PUSHER_NAME": pusher_name, "GITEA_PR_ID": "0",
                "SSH_ORIGINAL_COMMAND": "gitea-internal",
            })
            exit_code = applied.returncode
        except Exception:
            exit_code = 127
        current = self._gitea_ref(repository, ref)
        defense_commit = self._key_values((applied.stdout if applied is not None else "") or "").get("after")
        if defense_commit and not re.fullmatch(r"[0-9a-f]{40,64}", defense_commit):
            defense_commit = None
        readback_script = (
            'set -eu; bare="/data/git/repositories/$ANTIGENT_REPOSITORY.git"; '
            'test "$(git --git-dir="$bare" rev-parse "$ANTIGENT_DEFENSE^")" = "$ANTIGENT_BEFORE"; '
            'git --git-dir="$bare" merge-base --is-ancestor "$ANTIGENT_DEFENSE" "$ANTIGENT_HEAD"; '
            'git --git-dir="$bare" show "$ANTIGENT_DEFENSE:$ANTIGENT_PATH"'
        )
        content_matches = False
        if defense_commit and current and re.fullmatch(r"[0-9a-f]{40,64}", current):
            try:
                readback = self._docker_git(readback_script, env={
                    "ANTIGENT_REPOSITORY": repository, "ANTIGENT_DEFENSE": defense_commit,
                    "ANTIGENT_HEAD": current, "ANTIGENT_PATH": path, "ANTIGENT_BEFORE": before,
                })
                content_matches = readback.returncode == 0 and readback.stdout == content
            except Exception:
                content_matches = False
        verified = bool(defense_commit and current and content_matches)
        not_delivered = not defense_commit and current == before
        delivery_status = "verified" if verified else ("not_delivered" if not_delivered else "unverified")
        effect = {
            "schema_version": SCHEMA_EFFECT,
            "action_id": action_id,
            "operation": "gitea_repo_file",
            "target": {"repository": repository, "ref": ref, "path": path},
            "before": {"commit": before},
            "after": {"commit": defense_commit, "observed_head": current},
            "cleanup_required": bool(defense_commit or current != before),
            "attribution": "defense",
        }
        effect["effect_id"] = evidence_id(effect)
        delivery = {
            "schema_version": SCHEMA_DELIVERY,
            "record_type": "delivery_observation",
            "action_id": action_id,
            "execution_exit_code": exit_code,
            "surface": "gitea_repo_file",
            "required": True,
            "locator_sha256": evidence_id(locator),
            "content_sha256": _sha256_text(content),
            "marker_sha256": _sha256_text(marker),
            "native_object_id": defense_commit,
            "observed_head": current,
            "source_event_indexes": source_events,
            "principal_verification": "not_evaluated",
            "visible_at": time.time() if verified else None,
            "verified_at": time.time(),
            "status": delivery_status,
            "verification_method": "gitea_bare_ref_and_content_readback",
        }
        delivery["evidence_id"] = evidence_id(delivery)
        result.update({
            "container": self.gitea_container, "exit_code": exit_code,
            "duration": round(time.time() - started, 3),
            "stdout": "native readback matched" if verified else "native readback did not match",
            "stderr": "" if exit_code == 0 else "typed gitea operation failed; see native delivery status",
            "observations": [{"type": "delivery_observation", "observation": delivery}],
            "effect": effect,
        })
        return result

    def _apply_jenkins(self, action: dict, action_id: str) -> dict:
        started = time.time()
        full_name = action.get("job_full_name")
        result = self._base(
            "jenkins", f"[jenkins] operation=jenkins_disable_job target_sha256={_sha256_text(str(full_name))}"
        )
        source_events = action.get("evidence")

        def fail_before_apply(message: str, code: int = 1) -> dict:
            observation = {
                "schema_version": SCHEMA_CONTAINMENT,
                "record_type": "containment_observation",
                "action_id": action_id,
                "execution_exit_code": code,
                "surface": "jenkins_workflow_job",
                "target_sha256": _sha256_text(str(full_name)),
                "source_event_indexes": source_events if isinstance(source_events, list) else [],
                "status": "verified_ineffective",
                "disabled_readback": None,
                "build_watermark": [],
                "applied_at": None,
                "verified_at": time.time(),
                "verification_method": "jenkins_pre_apply_failure_no_mutation",
            }
            observation["evidence_id"] = evidence_id(observation)
            effect = {
                "schema_version": SCHEMA_EFFECT,
                "action_id": action_id,
                "operation": "jenkins_disable_job",
                "target": {"job_full_name": full_name},
                "before": {"disabled": None, "builds": []},
                "after": {"disabled": None},
                "applied_at": None,
                "cleanup_required": False,
                "attribution": "defense",
            }
            effect["effect_id"] = evidence_id(effect)
            result.update({
                "exit_code": code, "duration": round(time.time() - started, 3),
                "stderr": message,
                "observations": [{"type": "containment_observation", "observation": observation}],
                "effect": effect,
            })
            return result

        if self.jenkins is None:
            return fail_before_apply(
                "Jenkins containment is not configured (set JENKINS_URL, JENKINS_ADMIN_USER and "
                "JENKINS_ADMIN_PASSWORD for the defense plane)", 2)
        if not _valid_job(full_name):
            return fail_before_apply("job_full_name must be an exact Jenkins job path", 2)
        if (not isinstance(source_events, list) or not source_events
                or not all(isinstance(index, int) and index > 0 for index in source_events)):
            return fail_before_apply("evidence must list observed event indexes", 2)
        try:
            before_state = self.jenkins.job_state(full_name)
        except Exception as exc:  # noqa: BLE001 -- reported, never raised to the agent loop
            return fail_before_apply("Jenkins snapshot failed: " + jenkins_error(exc))
        if not _is_workflow_job(before_state, full_name):
            return fail_before_apply("containment requires an exact Jenkins WorkflowJob, not a folder", 2)
        before_disabled = before_state["disabled"]
        before_builds = _build_watermark(before_state.get("builds"))
        applied_at = time.time()
        exit_code = 0
        if not before_disabled:
            try:
                self.jenkins.set_job_disabled(full_name, True)
            except Exception:
                exit_code = 1
        try:
            after_state = self.jenkins.job_state(full_name)
            after_disabled = after_state["disabled"] if _is_workflow_job(after_state, full_name) else None
        except Exception:
            after_state, after_disabled = {}, None
        status = "verified" if after_disabled is True else (
            "verified_ineffective" if after_disabled is False else "unverified"
        )
        effect = {
            "schema_version": SCHEMA_EFFECT,
            "action_id": action_id,
            "operation": "jenkins_disable_job",
            "target": {"job_full_name": full_name},
            "before": {"disabled": before_disabled, "builds": before_builds},
            "after": {"disabled": after_disabled},
            "applied_at": applied_at,
            "cleanup_required": before_disabled is False and after_disabled is True,
            "attribution": "defense",
        }
        effect["effect_id"] = evidence_id(effect)
        observation = {
            "schema_version": SCHEMA_CONTAINMENT,
            "record_type": "containment_observation",
            "action_id": action_id,
            "execution_exit_code": exit_code,
            "surface": "jenkins_workflow_job",
            "target_sha256": _sha256_text(full_name),
            "source_event_indexes": source_events,
            "status": status,
            "disabled_readback": after_disabled,
            "build_watermark": before_builds,
            "applied_at": applied_at,
            "verified_at": time.time(),
            "verification_method": "jenkins_api_independent_readback",
        }
        observation["evidence_id"] = evidence_id(observation)
        result.update({
            "exit_code": exit_code, "duration": round(time.time() - started, 3),
            "stdout": f"containment {status}",
            "stderr": "" if exit_code == 0 else "Jenkins disable request failed; readback was still attempted",
            "observations": [{"type": "containment_observation", "observation": observation}],
            "effect": effect,
        })
        return result

    def _recover_gitea(self, effect: dict) -> dict:
        target = effect["target"]
        repository, ref = target["repository"], target["ref"]
        before = effect["before"]["commit"]
        expected_after = effect["after"].get("commit")
        current = self._gitea_ref(repository, ref)
        status, residual = "failed", True
        method = "gitea_atomic_update_ref_and_readback"
        if current == before:
            status, residual = "restored", False
        elif current and current == expected_after:
            script = (
                'set -eu; bare="/data/git/repositories/$ANTIGENT_REPOSITORY.git"; '
                'git --git-dir="$bare" update-ref "refs/heads/$ANTIGENT_REF" '
                '"$ANTIGENT_BEFORE" "$ANTIGENT_AFTER"; '
                'test "$(git --git-dir="$bare" rev-parse "refs/heads/$ANTIGENT_REF")" = "$ANTIGENT_BEFORE"'
            )
            try:
                proc = self._docker_git(script, env={
                    "ANTIGENT_REPOSITORY": repository, "ANTIGENT_REF": ref,
                    "ANTIGENT_BEFORE": before, "ANTIGENT_AFTER": expected_after,
                })
                current = self._gitea_ref(repository, ref)
                if proc.returncode == 0 and current == before:
                    status, residual = "restored", False
            except Exception:
                pass
        else:
            status = "conflict"
        return {"status": status, "residual_effect": residual, "verification_method": method,
                "restored_before_hash": current == before}

    def _recover_jenkins(self, effect: dict) -> dict:
        full_name = effect["target"]["job_full_name"]
        before = bool(effect["before"]["disabled"])
        try:
            state = self.jenkins.job_state(full_name)
            if not _is_workflow_job(state, full_name):
                raise ValueError("not a WorkflowJob")
            current = state["disabled"]
            if current != before:
                self.jenkins.set_job_disabled(full_name, before)
            verified = self.jenkins.job_state(full_name)
            restored = _is_workflow_job(verified, full_name) and verified["disabled"] == before
            return {"status": "restored" if restored else "failed", "residual_effect": not restored,
                    "restored_before_hash": restored,
                    "verification_method": "jenkins_api_restore_and_readback"}
        except Exception:
            return {"status": "failed", "residual_effect": True, "restored_before_hash": False,
                    "verification_method": "jenkins_api_restore_and_readback"}

    def finalize_containment(self, effect: dict) -> dict:
        """Verify disabled state and builds immediately before recovery, after the attack."""
        full_name = effect["target"]["job_full_name"]
        applied_at = float(effect.get("applied_at") or 0)
        known = {row["number"] for row in effect.get("before", {}).get("builds", [])}
        try:
            state = self.jenkins.job_state(full_name)
            complete = _is_workflow_job(state, full_name)
            disabled = state.get("disabled") if complete else None
            builds = _build_watermark(state.get("builds")) if complete else []
            new_builds = [row["number"] for row in builds if row["number"] not in known]
            in_flight = [row["number"] for row in builds if row["building"]]
            effective = complete and disabled is True and not new_builds and not in_flight
            status = "effective" if effective else ("ineffective" if complete else "unverified")
            result = {
                "schema_version": "containment_final_v1",
                "action_id": effect["action_id"],
                "status": status,
                "check_complete": complete,
                "disabled_readback": disabled,
                "new_build_numbers_after_apply": new_builds,
                "in_flight_build_numbers": in_flight,
                "applied_at": applied_at,
                "verified_at": time.time(),
                "verification_method": "jenkins_final_state_and_build_watermark",
            }
        except Exception:
            result = {
                "schema_version": "containment_final_v1", "action_id": effect["action_id"],
                "status": "unverified", "check_complete": False, "disabled_readback": None,
                "new_build_numbers_after_apply": [], "in_flight_build_numbers": [],
                "applied_at": applied_at, "verified_at": time.time(),
                "verification_method": "jenkins_final_state_and_build_watermark",
            }
        result["evidence_id"] = evidence_id(result)
        return result

    def recover(self, state: dict) -> dict:
        recoveries, finals = [], []
        # Nested defense commits must be unwound newest-first.  The compare-and-
        # swap in _recover_gitea still fails closed if any foreign commit is at
        # the ref, so reverse order never weakens the concurrent-change guard.
        for reservation in reversed(state.get("reservations", [])):
            effect = reservation.get("effect")
            if not isinstance(effect, dict):
                effect = None
                outcome = {"status": "unknown", "residual_effect": True,
                           "restored_before_hash": False, "verification_method": "missing_side_effect_snapshot"}
            elif effect.get("operation") == "jenkins_disable_job":
                if effect.get("applied_at") is not None:
                    finals.append(self.finalize_containment(effect))
                if not effect.get("cleanup_required"):
                    outcome = {"status": "not_required", "residual_effect": False,
                               "restored_before_hash": True, "verification_method": "snapshot_no_mutation"}
                else:
                    outcome = self._recover_jenkins(effect)
            elif not effect.get("cleanup_required"):
                outcome = {"status": "not_required", "residual_effect": False,
                           "restored_before_hash": True, "verification_method": "snapshot_no_mutation"}
            elif effect.get("operation") == "gitea_repo_file":
                outcome = self._recover_gitea(effect)
            else:
                outcome = {"status": "failed", "residual_effect": True,
                           "restored_before_hash": False, "verification_method": "unsupported_effect"}
            record = {
                "schema_version": SCHEMA_RECOVERY,
                "recovery_id": evidence_id({
                    "action_id": reservation.get("action_id"), "at": time.time(),
                }),
                "effect_id": effect.get("effect_id") if effect else None,
                "action_id": reservation.get("action_id"),
                "attempted_at": time.time(),
                "verified_at": time.time(),
                **outcome,
            }
            record["evidence_id"] = evidence_id(record)
            recoveries.append(record)
        complete = (len(recoveries) == len(state.get("reservations") or [])
                    and all(row["status"] in {"restored", "not_required"} and not row["residual_effect"]
                            for row in recoveries)
                    and all(row["check_complete"] for row in finals))
        return {
            "schema_version": "defense_recovery_report_v1",
            "complete": complete,
            "recoveries": recoveries,
            "containment_final": finals,
        }


def _resolve_container(docker: str, name: str) -> str:
    try:
        proc = subprocess.run(
            [docker, "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        names = proc.stdout.split()
        if name in names:
            return name
        candidates = [candidate for candidate in names if name in candidate]
        if len(candidates) == 1:   # never guess among several (could hit an unrelated container)
            return candidates[0]
    except Exception:
        pass
    return name


# What the scenario-agnostic gateway needs to know about this adapter's typed operations:
# which role each operation belongs to, and the exact form shown to the agent.
OPERATIONS = {"gitea_repo_file": "gitea", "jenkins_disable_job": "jenkins"}
# Fields that identify each operation's target (deduplication: one attempt per target).
OPERATION_TARGETS = {"gitea_repo_file": ("repository", "ref", "path"), "jenkins_disable_job": ("job_full_name",)}
ACTION_FORMS = (
    "Gitea: {role:'gitea', operation:'gitea_repo_file', repository:'owner/repo', ref:'main', "
    "path:'relative/file', content:'...', marker:'...', evidence:[event_index]}. "
    "Jenkins: {role:'jenkins', operation:'jenkins_disable_job', job_full_name:'exact/job', "
    "evidence:[event_index]}. The marker value must appear verbatim in content (it is how a later "
    "use is detected); otherwise the operation is refused and the target is spent."
)


def adapter_from_environment(docker: str, role_container: Callable[[str], str]) -> CicdGoatAdapter:
    """`role_container(role)` resolves a scenario role to its container name."""
    gitea_container = role_container("gitea") if callable(role_container) else str(role_container)
    jenkins = None
    url = os.environ.get("ANTIGENT_JENKINS_URL")
    user = os.environ.get("ANTIGENT_JENKINS_ADMIN_USER")
    password = os.environ.get("ANTIGENT_JENKINS_ADMIN_PASSWORD")
    if url and user and password:
        jenkins = JenkinsHttp(url, user, password)
    return CicdGoatAdapter(
        docker=docker,
        gitea_container=_resolve_container(docker, gitea_container),
        jenkins=jenkins,
    )


def write_recovery_report(path: Path, report: dict) -> None:
    path = Path(path)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    recover_parser = subparsers.add_parser("recover")
    recover_parser.add_argument("--state", type=Path, required=True)
    recover_parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.command != "recover":
        return 2
    adapter = adapter_from_environment(
        os.environ.get("DOCKER", "docker"), os.environ.get("GITEA_CONTAINER", "gitea")
    )
    try:
        state = json.loads(args.state.read_text(encoding="utf-8"))
        report = adapter.recover(state)
    except Exception:
        report = {
            "schema_version": "defense_recovery_report_v1",
            "complete": False,
            "recoveries": [],
            "containment_final": [],
            "error": "recovery_failed_closed",
        }
    write_recovery_report(args.report, report)
    return 0 if report.get("complete") else 1


if __name__ == "__main__":
    raise SystemExit(main())
