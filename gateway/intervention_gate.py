"""Persistent, fail-closed intervention state for the typed multi-turn protocol.

The state deliberately contains only hashes and target-native receipts, never raw
commands, decoy content, markers, or credentials. A reservation is recorded before
execution because a failed or interrupted exec may still have changed the target.
``context_managed_multi_turn_v1``: one typed action per observation, each target attempted
once, serial reobservation; no fixed limit on the number of reservations.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Any, Iterator

CONTEXT_PROTOCOL_ID = "context_managed_multi_turn_v1"
SCHEMA_VERSION = "intervention_state_v1"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def evidence_id(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def payload_digest(action: dict) -> str:
    """Hash the executable payload, excluding correlation and marker metadata."""
    if action.get("operation"):
        payload = {
            key: value for key, value in action.items()
            if key not in {"marker", "note"}
        }
    else:
        payload = {"role": action.get("role"), "cmd": action.get("cmd")}
    return evidence_id(payload)


def operation_key(action: dict, target_fields: dict | None) -> str | None:
    """Identity of a typed operation's target. Which fields identify the target is declared
    by the scenario adapter (operation -> field names); the gate itself names no operation."""
    operation = action.get("operation")
    fields = (target_fields or {}).get(operation) if isinstance(operation, str) else None
    if not fields:
        return None
    return evidence_id({"operation": operation, **{name: action.get(name) for name in fields}})


class InterventionGate:
    def __init__(
        self,
        state_path: Path,
        defense_log: Path | None = None,
        target_fields: dict | Callable[[], dict] | None = None,
    ):
        self.state_path = Path(state_path)
        self.protocol = CONTEXT_PROTOCOL_ID
        self.max_interventions = None
        self.defense_log = Path(defense_log) if defense_log else None
        # operation -> target field names, or a callable returning that (resolved lazily).
        self._target_fields = target_fields
        self.lock_path = self.state_path.with_suffix(self.state_path.suffix + ".lock")

    @property
    def target_fields(self) -> dict:
        value = self._target_fields() if callable(self._target_fields) else self._target_fields
        return dict(value or {})

    @contextmanager
    def _lock(self) -> Iterator[None]:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _new_state(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "protocol_id": self.protocol,
            "max_interventions": self.max_interventions,
            "reservations": [],
        }

    def _has_prior_exec(self) -> bool:
        if not self.defense_log or not self.defense_log.exists():
            return False
        try:
            with self.defense_log.open(encoding="utf-8") as handle:
                for line in handle:
                    try:
                        row = json.loads(line)
                    except ValueError:
                        return True
                    command = row.get("command") or {}
                    if (row.get("type") == "command" and command.get("side") == "defender"
                            and command.get("label") == "exec"):
                        return True
        except OSError:
            return True
        return False

    def _read(self, *, allow_initialize: bool = False) -> dict:
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            if allow_initialize and not self._has_prior_exec():
                return self._new_state()
            raise RuntimeError("intervention state is missing") from None
        except (OSError, ValueError) as exc:
            raise RuntimeError("intervention state is unreadable") from exc
        if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
            raise RuntimeError("intervention state schema is invalid")
        if value.get("protocol_id") != self.protocol:
            raise RuntimeError("intervention protocol does not match persistent state")
        if value.get("max_interventions") != self.max_interventions:
            raise RuntimeError("intervention budget does not match persistent state")
        reservations = value.get("reservations")
        if not isinstance(reservations, list) or not all(isinstance(row, dict) for row in reservations):
            raise RuntimeError("intervention reservations are invalid")
        return value

    def _write(self, state: dict) -> None:
        temporary = self.state_path.with_suffix(self.state_path.suffix + f".{os.getpid()}.tmp")
        try:
            with temporary.open("w", encoding="utf-8") as handle:
                os.chmod(temporary, 0o600)
                json.dump(state, handle, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.state_path)
        except Exception as exc:
            try:
                temporary.unlink()
            except OSError:
                pass
            raise RuntimeError("cannot persist intervention state") from exc

    def initialize(self) -> dict:
        with self._lock():
            state = self._read(allow_initialize=True)
            if not self.state_path.exists():
                self._write(state)
            return state

    def reserve(self, action: dict, action_id: str, turn: int | None) -> dict:
        """Atomically check and reserve one mutating exec; no target exec occurs here."""
        digest = payload_digest(action)
        op_key = operation_key(action, self.target_fields)
        if op_key is None:
            return {"allowed": False, "reason": "unsupported_operation", "payload_sha256": digest}
        if not isinstance(turn, int) or isinstance(turn, bool) or turn <= 0:
            return {"allowed": False, "reason": "invalid_turn", "payload_sha256": digest}
        try:
            with self._lock():
                state = self._read(allow_initialize=True)
                reservations = state["reservations"]
                if any(row.get("turn") == turn for row in reservations):
                    return {"allowed": False, "reason": "turn_duplicate", "payload_sha256": digest}
                if any(not row.get("reobserved_at") for row in reservations):
                    return {"allowed": False, "reason": "reobservation_pending", "payload_sha256": digest}
                if any(row.get("payload_sha256") == digest for row in reservations):
                    return {"allowed": False, "reason": "duplicate", "payload_sha256": digest}
                if any(row.get("operation_key") == op_key for row in reservations):
                    return {"allowed": False, "reason": "duplicate_operation", "payload_sha256": digest}
                reservation = {
                    "reservation_id": uuid.uuid4().hex,
                    "action_id": action_id,
                    "turn": turn,
                    "reserved_at": time.time(),
                    "payload_sha256": digest,
                    "operation_key": op_key,
                    "operation": action.get("operation"),
                    "status": "reserved",
                    "reobserved_at": None,
                    "reobservation_turn": None,
                }
                reservations.append(reservation)
                self._write(state)
                return {"allowed": True, "reservation": reservation}
        except Exception as exc:
            return {"allowed": False, "reason": "state_error", "error": str(exc),
                    "payload_sha256": digest}

    def complete(
        self,
        action_id: str,
        *,
        exit_code: int | None,
        effect: dict | None = None,
        observation_ids: list[str] | None = None,
    ) -> None:
        """Persist target-native outcomes without returning a reserved slot."""
        with self._lock():
            state = self._read()
            matches = [row for row in state["reservations"] if row.get("action_id") == action_id]
            if len(matches) != 1:
                raise RuntimeError("executed action has no unique reservation")
            row = matches[0]
            row["status"] = "completed"
            row["completed_at"] = time.time()
            row["execution_exit_code"] = exit_code
            if effect:
                row["effect"] = effect
                target = effect.get("target")
                if effect.get("operation") == row.get("operation") and isinstance(target, dict):
                    canonical_key = operation_key({"operation": effect["operation"], **target}, self.target_fields)
                    if canonical_key is not None:
                        row["operation_key"] = canonical_key
            if observation_ids:
                row["observation_ids"] = sorted(set(observation_ids))
            self._write(state)

    def link_reobservation(self, action_ids: list[str], turn: int, *, final: bool = False) -> None:
        if not isinstance(turn, int) or isinstance(turn, bool) or turn <= 0 or not action_ids:
            raise RuntimeError("a bounded reobservation needs action IDs and a positive turn")
        with self._lock():
            state = self._read()
            by_id = {row.get("action_id"): row for row in state["reservations"]}
            if any(action_id not in by_id for action_id in action_ids):
                raise RuntimeError("reobservation references an unreserved action")
            linked_at = time.time()
            prefix = "final_reobservation" if final else "reobservation"
            at_key = "final_reobserved_at" if final else "reobserved_at"
            turn_key = f"{prefix}_turn"
            for action_id in action_ids:
                row = by_id[action_id]
                if row.get(at_key) and row.get(turn_key) != turn:
                    raise RuntimeError(f"action was already linked to another {prefix}")
                row[at_key] = row.get(at_key) or linked_at
                row[turn_key] = turn
                if final:
                    row["final_reobserved_at"] = row.get("final_reobserved_at") or linked_at
                    row["final_reobservation_turn"] = turn
                else:
                    row["final_reobserved_at"] = row.get("final_reobserved_at")
                    row["final_reobservation_turn"] = row.get("final_reobservation_turn")
            self._write(state)

    def snapshot(self) -> dict:
        with self._lock():
            return self._read()
