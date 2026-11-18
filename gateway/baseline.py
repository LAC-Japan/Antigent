"""Scenario-adapter driven clean-target baseline calibration.

Only explicitly configured, ordinary telemetry can become a persistent baseline
filter. A candidate must repeat for the configured count and time span; client
address alone is never sufficient. The profile contains metadata, not log lines.
"""
from __future__ import annotations

import json
import time
from typing import Any


class CleanBaseline:
    VERSION = 1

    def __init__(self, config: dict | None = None, *, duration_sec: float | None = None,
                 started_at: float | None = None):
        cfg = config or {}
        self.duration_sec = max(0.0, float(
            cfg.get("duration_sec", 0) if duration_sec is None else duration_sec))
        self.min_count = max(2, int(cfg.get("min_count", 3)))
        self.min_span_sec = max(0.0, float(cfg.get("min_span_sec", 20)))
        self.learn = {
            str(kind): tuple(str(field) for field in fields)
            for kind, fields in (cfg.get("learn") or {}).items()
            if isinstance(fields, list) and fields
        }
        self.started_at = float(time.time() if started_at is None else started_at)
        self.completed_at: float | None = None
        self.candidates: dict[str, dict] = {}
        self.entries: list[dict] = []
        self._accepted: set[str] = set()

    @staticmethod
    def _key(source: str, kind: str, attrs: dict) -> str:
        return json.dumps([source, kind, attrs], ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"))

    def _attributes(self, event: dict) -> dict[str, Any] | None:
        if event.get("internal"):
            return None
        fields = self.learn.get(str(event.get("kind")))
        if not fields:
            return None
        attrs = {field: event.get(field) for field in fields}
        if any(value is None or value == "" for value in attrs.values()):
            return None
        return attrs

    def observe(self, event: dict) -> None:
        """Collect one event emitted during the attacker-free calibration window."""
        if self.completed_at is not None or event.get("level") != "baseline":
            return
        attrs = self._attributes(event)
        if attrs is None:
            return
        source, kind = str(event.get("source")), str(event.get("kind"))
        key = self._key(source, kind, attrs)
        ts = float(event.get("ts") or time.time())
        candidate = self.candidates.setdefault(key, {
            "source": source, "kind": kind, "attributes": attrs,
            "count": 0, "first_ts": ts, "last_ts": ts,
        })
        candidate["count"] += 1
        candidate["first_ts"] = min(candidate["first_ts"], ts)
        candidate["last_ts"] = max(candidate["last_ts"], ts)

    def finish(self, completed_at: float | None = None) -> "CleanBaseline":
        self.completed_at = float(time.time() if completed_at is None else completed_at)
        self.entries = sorted((
            candidate for candidate in self.candidates.values()
            if candidate["count"] >= self.min_count
            and candidate["last_ts"] - candidate["first_ts"] >= self.min_span_sec
        ), key=lambda candidate: (candidate["source"], candidate["kind"],
                                  json.dumps(candidate["attributes"], sort_keys=True)))
        self._accepted = {
            self._key(entry["source"], entry["kind"], entry["attributes"])
            for entry in self.entries
        }
        self.candidates = {}
        return self

    def matches(self, source: str, kind: str, event: dict) -> bool:
        if self.completed_at is None:
            return False
        attrs = self._attributes({"source": source, "kind": kind, **event})
        return attrs is not None and self._key(source, kind, attrs) in self._accepted

    def to_dict(self) -> dict:
        return {
            "version": self.VERSION,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_sec": self.duration_sec,
            "min_count": self.min_count,
            "min_span_sec": self.min_span_sec,
            "learn": {kind: list(fields) for kind, fields in self.learn.items()},
            "entries": self.entries,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CleanBaseline":
        if int(data.get("version") or 0) != cls.VERSION:
            raise ValueError("unsupported clean baseline profile version")
        obj = cls({"duration_sec": data.get("duration_sec", 0),
                   "min_count": data.get("min_count", 3),
                   "min_span_sec": data.get("min_span_sec", 20),
                   "learn": data.get("learn") or {}},
                  started_at=float(data.get("started_at") or 0))
        completed = data.get("completed_at")
        if completed is None:
            raise ValueError("clean baseline profile is incomplete")
        obj.completed_at = float(completed)
        entries = data.get("entries")
        if not isinstance(entries, list):
            raise ValueError("clean baseline entries are invalid")
        obj.entries = entries
        obj._accepted = {
            obj._key(str(entry["source"]), str(entry["kind"]), dict(entry["attributes"]))
            for entry in entries
        }
        return obj
