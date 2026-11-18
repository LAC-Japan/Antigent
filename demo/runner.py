"""Demo runner: orchestrates the full demo lifecycle."""
from __future__ import annotations

import json
import signal
import time
from pathlib import Path

from .config import DemoConfig
from .docker_ops import DemoOrchestrator, DockerError


class DemoRunner:
    """Orchestrates the complete demo: dry-run validation or live run."""
    
    def __init__(self, config: DemoConfig):
        self.config = config
        self.orchestrator = DemoOrchestrator(config)
        self._interrupted = False
        self._console_url = f"http://127.0.0.1:{config.console_port}"
    
    def dry_run(self) -> int:
        """
        Validate configuration without starting containers or calling models.
        
        Returns exit code (0 = success, non-zero = error).
        """
        print("=== Antigent Demo dry-run ===")
        print(f"Run ID: {self.config.run_id}")
        print(f"Defense plane: {self.config.defense_plane_dir}")
        print(f"CI/CD Goat: {self.config.cicd_goat_dir}")
        print()
        
        # Check prerequisites
        issues = self.orchestrator.check_prerequisites()
        if issues:
            print("Configuration issues found:\n")
            for issue in issues:
                print(f"  - {issue}")
            return 1
        
        print("Configuration valid:")
        print(f"  Attacker model: {self.config.attacker_model}")
        print(f"  Defender model: {self.config.defender_model}")
        print(f"  Console port: {self.config.console_port}")
        print(f"  Attack timeout: {self.config.attack_timeout}s")
        print()
        
        # Check if we're using free models or need API keys
        if self.config.attacker_model.startswith("openai/"):
            if self.config.openai_attacker_key:
                print("  Attacker OpenAI key: (set)")
            else:
                print("  WARNING: Attacker uses OpenAI but OPENAI_ATTACKER_KEY not set")
        
        if self.config.defender_model.startswith("openai/"):
            if self.config.openai_defender_key:
                print("  Defender OpenAI key: (set)")
            else:
                print("  WARNING: Defender uses OpenAI but OPENAI_DEFENDER_KEY not set")
        
        print()
        print("dry-run complete. No containers, volumes, or model calls made.")
        print("Run 'uv run python live_demo.py run' to start the demo.")
        return 0
    
    def run(self) -> int:
        """
        Execute the full demo: fresh target, defense, AUTO attack, cleanup.
        
        Returns exit code (0 = success, non-zero = error).
        """
        print(f"=== Antigent Demo run ({self.config.run_id}) ===")
        
        # Setup interrupt handler
        def on_interrupt(_signum, _frame):
            print("\nInterrupt received, stopping...")
            self._interrupted = True
        
        signal.signal(signal.SIGINT, on_interrupt)
        signal.signal(signal.SIGTERM, on_interrupt)
        
        # Check prerequisites
        issues = self.orchestrator.check_prerequisites()
        if issues:
            print("Configuration issues found:\n")
            for issue in issues:
                print(f"  - {issue}")
            return 1
        
        # Record run start
        manifest = self._init_manifest()
        
        try:
            # Step 1: Start fresh CI/CD Goat Caterpillar
            print("\n[1/5] Starting fresh CI/CD Goat Caterpillar...")
            if self._interrupted:
                return self._abort("interrupted before target start")
            
            if self.orchestrator.check_target_running():
                print("  Target already running, ensuring fresh state...")
                self.orchestrator.stop_target()
                time.sleep(2)
            
            if not self.orchestrator.start_target(timeout=180):
                return self._abort("target failed to start")
            print("  Target started: gitea, jenkins-server, prod")
            
            # Step 2: Start Defense Plane
            print("\n[2/5] Starting Defense Plane...")
            if self._interrupted:
                return self._abort("interrupted before defense start")
            
            if not self.orchestrator.start_defense():
                return self._abort("defense failed to start")
            print(f"  Defense ready, Console at {self._console_url}")
            if not (self.config.jenkins_url and self.config.jenkins_admin_user
                    and self.config.jenkins_admin_password):
                print("  NOTE: Jenkins containment is off (JENKINS_URL / JENKINS_ADMIN_USER / "
                      "JENKINS_ADMIN_PASSWORD unset); jenkins_disable_job will be refused.")
            else:
                jc = self.orchestrator.check_jenkins_access()
                if jc.get("ok") and jc.get("admin"):
                    print(f"  Jenkins containment ready (logged in as {jc.get('name')}, administrator)")
                elif jc.get("ok") and jc.get("admin") is None:
                    print(f"  NOTE: Jenkins login works as {jc.get('name')}; administrator rights could not be"
                          " confirmed (jenkins_disable_job will report it if they are missing).")
                elif jc.get("ok"):
                    print(f"  WARNING: Jenkins login works as {jc.get('name')} but it is not an administrator;"
                          " jenkins_disable_job will fail. Use the lab's admin account.")
                else:
                    print(f"  WARNING: Jenkins containment will fail: {jc.get('error')}"
                          " (check JENKINS_URL / JENKINS_ADMIN_USER / JENKINS_ADMIN_PASSWORD)")
            
            # Step 3: Wait for baseline (sensor must observe target)
            print("\n[3/5] Waiting for defense baseline...")
            if self._interrupted:
                return self._abort("interrupted during baseline")
            
            #_baseline is already waited in start_defense()
            print("  Baseline observation complete")
            self._report_defender_briefing()
            
            # Step 4: Start AUTO attack
            print("\n[4/5] Starting AUTO attacker...")
            if self._interrupted:
                return self._abort("interrupted before attack start")
            
            if not self.orchestrator.start_attack():
                return self._abort("attacker failed to start")
            print(f"  Attacker running (timeout: {self.config.attack_timeout}s)")
            
            # Step 5: Monitor until completion or timeout
            print("\n[5/5] Monitoring attack...")
            print(f"  Console: {self._console_url}")
            print("  Press Ctrl-C to stop early\n")
            
            self._attack_t0 = time.time()
            deadline = time.monotonic() + self.config.attack_timeout
            attack_done = False
            next_status = time.monotonic() + 30
            while time.monotonic() < deadline and not self._interrupted:
                # The attack runs as a direct `docker compose exec` (no wrapper
                # shell), so opencode's natural exit is observable here.
                if not self.orchestrator.attack_running():
                    attack_done = True
                    break
                if time.monotonic() >= next_status:
                    print("  " + self._status_line())
                    next_status = time.monotonic() + 30
                time.sleep(5)
            
            if self._interrupted:
                print("\nAttack interrupted by user")
            elif attack_done:
                print("\nAttack finished (opencode exited)")
            else:
                print("\nAttack timeout reached")
            print("  " + self._status_line())
            self._diagnose_attack()
            
            # Drain defense, require the final receipt, and restore owned target effects
            # while the adapter and target are still running.
            print("\nDraining defense and final reobservation...")
            self.orchestrator.stop_attack()
            self.orchestrator.finalize_defense(self.config.defense_turn_timeout)
            recovery = self.orchestrator.recover_defense()
            if recovery is None:
                print("  Final reobservation accepted; no target recovery required")
            else:
                print(f"  Final reobservation accepted; recovery complete "
                      f"({len(recovery.get('recoveries') or [])} effects)")
            
            # Record completion
            self._complete_manifest(manifest)
            
            print(f"\nDemo run complete. Console remains at {self._console_url}")
            print("Run 'uv run python live_demo.py stop' to clean up.")
            return 0
            
        except DockerError as e:
            return self._abort(str(e))
        except Exception as e:
            return self._abort(f"unexpected error: {e}")
    
    def stop(self) -> int:
        """
        Stop all demo resources.
        
        Returns exit code (0 = success).
        """
        print(f"=== Stopping demo ({self.config.run_id}) ===")
        
        try:
            self.orchestrator.full_stop()
            print("All resources stopped.")
            return 0
        except DockerError as e:
            print(f"Warning during cleanup: {e}")
            return 0  # Still return success, cleanup is best-effort
    
    def _abort(self, reason: str) -> int:
        """Abort the demo with cleanup."""
        print(f"\nABORT: {reason}")
        print("Cleaning up...")
        self.orchestrator.stop_all()
        return 1
    
    # --- diagnostics -------------------------------------------------------------------
    # Shown in the terminal so that an attacker that never ran a command, or a defender
    # whose model call failed, is visible without opening container logs.
    def _attacker_dir(self) -> Path:
        return self.config.defense_plane_dir / "runs" / "attacker"

    def _since(self, path: Path, since: float) -> list[dict]:
        rows = []
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if isinstance(ev, dict) and float(ev.get("ts") or 0) >= since:
                    rows.append(ev)
        except OSError:
            pass
        return rows

    def _status_line(self) -> str:
        t0 = getattr(self, "_attack_t0", 0.0)
        cmds = [e for e in self._since(self._attacker_dir() / "attacker.jsonl", t0)
                if e.get("event") in ("start", "cmd")]
        egress = self._since(self.config.defense_plane_dir / "runs" / "egress" / "egress.jsonl", t0)
        allow = sum(1 for e in egress if e.get("decision") == "allow")
        deny = sum(1 for e in egress if e.get("decision") == "deny")
        fail = sum(1 for e in egress if e.get("reason") in ("dns-failure", "connect-failed"))
        open_now = allow - sum(1 for e in egress if e.get("decision") == "close")
        denied = sorted({str(e.get("host") or e.get("request") or "?")
                         for e in egress if e.get("decision") == "deny"})
        return (f"attacker commands: {len(cmds)} | LLM tunnels: {allow} opened ({max(open_now, 0)} open), "
                f"{deny} refused"
                + (f" [{', '.join(denied[:4])}{', ...' if len(denied) > 4 else ''}]" if denied else "")
                + (f", {fail} upstream failures" if fail else ""))

    def _diagnose_attack(self) -> None:
        t0 = getattr(self, "_attack_t0", 0.0)
        cmds = [e for e in self._since(self._attacker_dir() / "attacker.jsonl", t0)
                if e.get("event") in ("start", "cmd")]
        if cmds:
            return
        print("\n  WARNING: the attacker ran no shell commands (runs/attacker/attacker.jsonl is empty).")
        egress = self._since(self.config.defense_plane_dir / "runs" / "egress" / "egress.jsonl", t0)
        if not any(e.get("decision") == "allow" for e in egress):
            print("  The attacker never reached its model API through egress-proxy.")
        upstream = [e for e in egress if e.get("reason") in ("dns-failure", "connect-failed")]
        if upstream:
            print("  egress-proxy could not connect to the model API "
                  f"({upstream[-1].get('host')}: {upstream[-1].get('reason')}). Behind a corporate "
                  "proxy, set ATTACKER_EGRESS_UPSTREAM_PROXY in .env.")
        denied = sorted({f"{e.get('host')}:{e.get('port')}" for e in egress
                         if e.get("decision") == "deny" and e.get("host")})
        if denied:
            print("  Hosts refused by egress-proxy: " + ", ".join(denied[:10])
                  + " (add a needed one to ATTACKER_EGRESS_EXTRA_ALLOW)")
        code = self.orchestrator.attack_exit_code()
        if code is not None:
            print(f"  OpenCode (docker compose exec) exit code: {code}"
                  + ("  (124 = attack timeout)" if code == 124 else ""))
        out = self._attacker_dir() / "opencode.out"
        try:
            text = out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            print(f"  {out} does not exist: OpenCode was never started in the Attack Box.")
            return
        tail = text.splitlines()[-25:]
        if not tail:
            print(f"  {out} is empty: OpenCode printed nothing (it did not start a session).")
            return
        print(f"  Last lines of {out}:")
        for line in tail:
            print("    " + line[:300])

    def _report_defender_briefing(self, wait: float = 180.0) -> None:
        """Wait for the defender's T0 briefing and say plainly if its model call failed."""
        driver = self.config.run_dir / "defense" / "driver.jsonl"
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline and not self._interrupted:
            ends = [e for e in self._since(driver, 0) if e.get("type") == "turn_end" and e.get("turn") == 0]
            if ends:
                end = ends[-1]
                prof = end.get("profile") or {}
                if end.get("exit_code") == 0:
                    print(f"  Defender T0 briefing done ({prof.get('steps', '?')} LLM steps)")
                else:
                    print(f"  WARNING: defender T0 briefing failed (exit {end.get('exit_code')}, "
                          f"{prof.get('steps', 0)} LLM steps, {prof.get('error_count', 0)} errors). "
                          "The defender model is not answering; check: docker logs antigent-core")
                return
            time.sleep(3)
        print("  WARNING: no defender T0 briefing result yet (check: docker logs antigent-core)")

    def _init_manifest(self) -> dict:
        """Initialize run manifest."""
        manifest = {
            "run_id": self.config.run_id,
            "status": "running",
            "attacker_model": self.config.attacker_model,
            "defender_model": self.config.defender_model,
            "protocol": "context_managed_multi_turn_v1",
        }
        
        manifest_path = self.config.run_dir / "manifest.json"
        self.config.run_dir.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest, indent=2))
        
        return manifest
    
    def _complete_manifest(self, manifest: dict) -> None:
        """Update manifest with completion status."""
        manifest["status"] = "completed"
        
        manifest_path = self.config.run_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))
