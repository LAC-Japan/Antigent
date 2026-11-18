#!/usr/bin/env python3
"""
Antigent Defense Plane - Public Demo CLI

A single-command demo experience for CI/CD Goat Caterpillar:
  1. uv run python live_demo.py dry-run   # validate config, no changes
  2. uv run python live_demo.py run       # fresh target + defense + AUTO attack
  3. uv run python live_demo.py stop      # cleanup

The demo uses the context_managed_multi_turn_v1 protocol with native
receipt, reobservation, and recovery. See README.md for requirements.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path



def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (stdlib only). Existing environment wins."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Antigent Defense Plane demo for CI/CD Goat Caterpillar",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  dry-run  Validate configuration without starting containers or calling models
  run      Start fresh target, defense plane, and AUTO attacker
  stop     Stop all demo resources

Environment variables (copy .env.example to .env):
  CICD_GOAT_DIR         Path to CI/CD Goat repository (required)
  ATTACKER_MODEL        Model ref for attacker (default: opencode/glm-5.3-flash-free)
  DEFENDER_MODEL        Model ref for defender (default: opencode/glm-5.3-flash-free)
  OPENAI_ATTACKER_KEY   OpenAI API key (only if ATTACKER_MODEL starts with openai/)
  OPENAI_DEFENDER_KEY   OpenAI API key (only if DEFENDER_MODEL starts with openai/)
  ATTACK_TIMEOUT        Attack timeout in seconds (default: 1800)
  CONSOLE_PORT          Console web UI port (default: 8765)
  JENKINS_URL           Jenkins URL for containment operations
  JENKINS_ADMIN_USER    Jenkins admin username
  JENKINS_ADMIN_PASSWORD Jenkins admin password

Examples:
  # Using OpenCode free models (no API key needed)
  cp .env.example .env
  # Edit CICD_GOAT_DIR in .env
  uv run python live_demo.py dry-run
  uv run python live_demo.py run
  
  # Using OpenAI GPT-4
  export CICD_GOAT_DIR=/path/to/cicd-goat
  export ATTACKER_MODEL=openai/gpt-4o
  export DEFENDER_MODEL=openai/gpt-4o
  export OPENAI_ATTACKER_KEY=sk-...
  export OPENAI_DEFENDER_KEY=sk-...
  uv run python live_demo.py run

See README.md for model selection, the OpenCode AUTO mode, and security notes.
""",
    )
    parser.add_argument(
        "command",
        choices=["dry-run", "run", "stop", "view"],
        help="Demo command to execute (view: review a Console export offline)",
    )
    parser.add_argument("file", nargs="?", help="view: the exported *-merged.jsonl")
    parser.add_argument("--port", type=int, default=8766, help="view: Console port (default 8766)")

    args = parser.parse_args()
    if args.command == "view":
        # Offline review needs no containers, no .env and no model: just the Console server.
        if not args.file:
            parser.error("view needs the exported file: live_demo.py view <session>-merged.jsonl")
        here = Path(__file__).resolve().parent
        return subprocess.call([sys.executable, str(here / "server.py"), "--import",
                                str(Path(args.file).resolve()), "--port", str(args.port)])

    from demo.config import DemoConfig
    from demo.runner import DemoRunner

    # Determine defense-plane directory and load .env before reading config
    defense_plane_dir = Path(__file__).resolve().parent
    _load_dotenv(defense_plane_dir / ".env")

    # Load configuration
    config = DemoConfig.from_env(defense_plane_dir)
    
    # Create runner
    runner = DemoRunner(config)
    
    # Execute command
    if args.command == "dry-run":
        return runner.dry_run()
    elif args.command == "run":
        return runner.run()
    elif args.command == "stop":
        return runner.stop()
    else:
        parser.error(f"unknown command: {args.command}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
