"""Sensor-daemon clean calibration status and restart behavior."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gateway"))
import defense_gateway as gw  # noqa: E402
import sensor  # noqa: E402


class FakeObserver(gw.Observer):
    """One baseline event per cycle, without Docker or wall-clock sleeps."""

    def restore(self, events):
        self.next_idx = max((int(event.get("index", 0)) for event in events), default=0) + 1
        self.resume_after = max((float(event.get("ts", 0)) for event in events), default=0)

    def collect(self, roles):
        del roles
        self._add("gitea", "access-log", "synthetic clean poll",
                  dedup_key=f"synthetic|{self.next_idx}", client="192.0.2.10",
                  method="GET", path="/health")


class SensorCalibrationTest(unittest.TestCase):
    def test_restart_during_learning_does_not_become_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stream = root / "sensor.jsonl"
            with mock.patch.multiple(sensor,
                                     STREAM=stream,
                                     STATUS=root / "sensor.status.json",
                                     PROFILE=root / "sensor.baseline.json",
                                     BASELINE_SEC=60), \
                 mock.patch.object(sensor.gw, "Observer", FakeObserver), \
                 mock.patch.object(sys, "argv", ["sensor.py", "--once"]):
                sensor.main()
                first = json.loads((root / "sensor.status.json").read_text())
                self.assertTrue(stream.exists())
                self.assertEqual(first["baseline"]["state"], "learning")
                self.assertFalse(first["baseline"]["ready"])
                self.assertFalse((root / "sensor.baseline.json").exists())

                # Simulate a process restart after one collected event but before finish/profile.
                sensor.main()
                second = json.loads((root / "sensor.status.json").read_text())
                self.assertEqual(second["baseline"]["state"], "learning")
                self.assertFalse(second["baseline"]["ready"])
                self.assertEqual(second["max_index"], 2)
                self.assertFalse((root / "sensor.baseline.json").exists())

    def test_legacy_stream_without_learning_marker_stays_legacy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stream = root / "sensor.jsonl"
            event = {"index": 1, "ts": 1, "source": "gitea", "kind": "access-log",
                     "level": "raw", "summary": "old", "key": "old"}
            stream.write_text(json.dumps({"type": "observed", "event": event}) + "\n")
            with mock.patch.multiple(sensor,
                                     STREAM=stream,
                                     STATUS=root / "sensor.status.json",
                                     PROFILE=root / "sensor.baseline.json",
                                     BASELINE_SEC=60), \
                 mock.patch.object(sensor.gw, "Observer", FakeObserver), \
                 mock.patch.object(sys, "argv", ["sensor.py", "--once"]):
                sensor.main()
                status = json.loads((root / "sensor.status.json").read_text())
                self.assertEqual(status["baseline"]["state"], "ready")
                self.assertTrue(status["baseline"]["ready"])
                self.assertEqual(status["baseline"]["duration_sec"], 0)


if __name__ == "__main__":
    unittest.main()
