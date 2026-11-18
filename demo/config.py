"""Configuration parsing and validation for the public demo."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# Valid provider prefixes for model refs
VALID_MODEL_PREFIXES = [
    "opencode/",
    "amazon-bedrock/",
    "openai/",
]   # anthropic/* is not offered: the demo has no way to pass an Anthropic key to either role


@dataclass(frozen=True)
class DemoConfig:
    """Immutable configuration for a demo run."""
    # Paths
    cicd_goat_dir: Path
    defense_plane_dir: Path
    run_dir: Path
    
    # Model configuration
    attacker_model: str
    defender_model: str
    
    # API keys (OpenAI native provider, optional)
    openai_attacker_key: Optional[str] = None
    openai_defender_key: Optional[str] = None
    
    # AWS Bedrock credentials (for amazon-bedrock/* models)
    aws_bearer_token_bedrock: Optional[str] = None
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_session_token: Optional[str] = None
    aws_region: str = "us-east-1"

    # Attacker-only AWS Bedrock credential. Every command the attacker agent runs can read
    # it, so it is kept separate from the defender's. Sharing the defender credential is
    # refused unless ATTACKER_SHARE_DEFENDER_CREDENTIALS=1 is set explicitly.
    attacker_aws_bearer_token_bedrock: Optional[str] = None
    attacker_aws_access_key_id: Optional[str] = None
    attacker_aws_secret_access_key: Optional[str] = None
    attacker_aws_session_token: Optional[str] = None
    share_defender_credentials: bool = False

    # Extra hosts the attacker egress proxy may reach (comma list), e.g. a model catalog.
    attacker_egress_extra_allow: str = ""
    # Corporate HTTP proxy the egress proxy must chain through (http://[user:pass@]host:port).
    attacker_egress_upstream_proxy: str = ""

    # Timeouts (seconds)
    attack_startup_timeout: int = 300
    defense_turn_timeout: int = 120
    attack_timeout: int = 1800  # 30 minutes max
    
    # Console
    console_port: int = 8765
    
    # Jenkins credential (for Caterpillar containment)
    jenkins_url: Optional[str] = None
    jenkins_admin_user: Optional[str] = None
    jenkins_admin_password: Optional[str] = None
    
    # Run identification
    run_id: str = "demo"
    
    def validate(self) -> list[str]:
        """Return list of validation error messages, empty if valid."""
        errors: list[str] = []
        
        # CI/CD Goat directory must exist
        if not self.cicd_goat_dir.is_dir():
            errors.append(f"CICD_GOAT_DIR not found: {self.cicd_goat_dir}")
        
        # Model refs must have valid prefix
        if not any(self.attacker_model.startswith(p) for p in VALID_MODEL_PREFIXES):
            errors.append(
                f"ATTACKER_MODEL must start with one of {VALID_MODEL_PREFIXES}: "
                f"{self.attacker_model}"
            )
        if not any(self.defender_model.startswith(p) for p in VALID_MODEL_PREFIXES):
            errors.append(
                f"DEFENDER_MODEL must start with one of {VALID_MODEL_PREFIXES}: "
                f"{self.defender_model}"
            )
        
        # OpenAI keys required if using openai/ prefix
        if self.attacker_model.startswith("openai/") and not self.openai_attacker_key:
            errors.append("ATTACKER_MODEL uses openai/ but OPENAI_ATTACKER_KEY not set")
        if self.defender_model.startswith("openai/") and not self.openai_defender_key:
            errors.append("DEFENDER_MODEL uses openai/ but OPENAI_DEFENDER_KEY not set")
        # An OpenAI key without an openai/* model has no effect (silent free-model run)
        if self.openai_attacker_key and not self.attacker_model.startswith("openai/"):
            errors.append("OPENAI_ATTACKER_KEY is set but ATTACKER_MODEL is not openai/*")
        if self.openai_defender_key and not self.defender_model.startswith("openai/"):
            errors.append("OPENAI_DEFENDER_KEY is set but DEFENDER_MODEL is not openai/*")
        
        # AWS Bedrock models require credentials (bearer token or access key pair)
        if self.defender_model.startswith("amazon-bedrock/") and not (
                self.aws_bearer_token_bedrock or (self.aws_access_key_id and self.aws_secret_access_key)):
            errors.append(
                "amazon-bedrock/* models require ANTIGENT_AWS_BEARER_TOKEN_BEDROCK "
                "or ANTIGENT_AWS_ACCESS_KEY_ID+ANTIGENT_AWS_SECRET_ACCESS_KEY"
            )
        if self.attacker_model.startswith("amazon-bedrock/") and not self.attacker_aws_credential():
            errors.append(
                "ATTACKER_MODEL uses amazon-bedrock/* but no attacker credential is set: set "
                "ATTACKER_AWS_BEARER_TOKEN_BEDROCK (preferred) or ATTACKER_AWS_ACCESS_KEY_ID+"
                "ATTACKER_AWS_SECRET_ACCESS_KEY. The attacker agent can read this credential; "
                "reusing the defender's requires ATTACKER_SHARE_DEFENDER_CREDENTIALS=1"
            )
        
        # Port must be valid
        if not (1 <= self.console_port <= 65535):
            errors.append(f"CONSOLE_PORT must be 1-65535: {self.console_port}")
        
        # Timeouts must be positive
        for name in ["attack_startup_timeout", "defense_turn_timeout", "attack_timeout"]:
            value = getattr(self, name)
            if value <= 0:
                errors.append(f"{name.upper()} must be positive: {value}")
        
        return errors

    def attacker_aws_credential(self) -> dict[str, str]:
        """The single Bedrock credential handed to the Attack Box (bearer token preferred;
        never both forms). Empty when none is configured for the attacker."""
        if self.attacker_aws_bearer_token_bedrock:
            return {"AWS_BEARER_TOKEN_BEDROCK": self.attacker_aws_bearer_token_bedrock}
        if self.attacker_aws_access_key_id and self.attacker_aws_secret_access_key:
            cred = {"AWS_ACCESS_KEY_ID": self.attacker_aws_access_key_id,
                    "AWS_SECRET_ACCESS_KEY": self.attacker_aws_secret_access_key}
            if self.attacker_aws_session_token:
                cred["AWS_SESSION_TOKEN"] = self.attacker_aws_session_token
            return cred
        if self.share_defender_credentials:
            if self.aws_bearer_token_bedrock:
                return {"AWS_BEARER_TOKEN_BEDROCK": self.aws_bearer_token_bedrock}
            if self.aws_access_key_id and self.aws_secret_access_key:
                cred = {"AWS_ACCESS_KEY_ID": self.aws_access_key_id,
                        "AWS_SECRET_ACCESS_KEY": self.aws_secret_access_key}
                if self.aws_session_token:
                    cred["AWS_SESSION_TOKEN"] = self.aws_session_token
                return cred
        return {}

    @classmethod
    def from_env(cls, defense_plane_dir: Path) -> "DemoConfig":
        """Load configuration from environment variables."""
        
        # Required: CICD_GOAT_DIR
        cicd_goat_dir = Path(os.getenv("CICD_GOAT_DIR", "")).resolve()
        
        # Run directory (unique per run)
        run_id = os.getenv("DEMO_RUN_ID", "demo")
        run_dir = defense_plane_dir / "runs" / run_id
        
        # Model refs - must be explicit
        attacker_model = os.getenv("ATTACKER_MODEL", "opencode/glm-5.3-flash-free")
        defender_model = os.getenv("DEFENDER_MODEL", "opencode/glm-5.3-flash-free")
        
        # Optional OpenAI keys
        openai_attacker_key = os.getenv("OPENAI_ATTACKER_KEY") or None
        openai_defender_key = os.getenv("OPENAI_DEFENDER_KEY") or None
        
        # AWS Bedrock credentials
        aws_bearer_token_bedrock = os.getenv("ANTIGENT_AWS_BEARER_TOKEN_BEDROCK") or None
        aws_access_key_id = os.getenv("ANTIGENT_AWS_ACCESS_KEY_ID") or None
        aws_secret_access_key = os.getenv("ANTIGENT_AWS_SECRET_ACCESS_KEY") or None
        aws_session_token = os.getenv("ANTIGENT_AWS_SESSION_TOKEN") or None
        aws_region = os.getenv("ANTIGENT_AWS_REGION", "us-east-1")
        attacker_aws = {k: (os.getenv(f"ATTACKER_AWS_{k}") or None) for k in
                        ("BEARER_TOKEN_BEDROCK", "ACCESS_KEY_ID", "SECRET_ACCESS_KEY", "SESSION_TOKEN")}

        # Timeouts
        attack_startup_timeout = int(os.getenv("ATTACK_STARTUP_TIMEOUT", "300"))
        defense_turn_timeout = int(os.getenv("DEFENSE_TURN_TIMEOUT", "120"))
        attack_timeout = int(os.getenv("ATTACK_TIMEOUT", "1800"))
        
        # Console port
        console_port = int(os.getenv("CONSOLE_PORT", "8765"))
        
        # Jenkins credential (for Caterpillar)
        # JENKINS_* (demo .env) or ANTIGENT_JENKINS_* (the names the defense container uses).
        jenkins_url = os.getenv("JENKINS_URL") or os.getenv("ANTIGENT_JENKINS_URL") or None
        jenkins_admin_user = os.getenv("JENKINS_ADMIN_USER") or os.getenv("ANTIGENT_JENKINS_ADMIN_USER") or None
        jenkins_admin_password = (os.getenv("JENKINS_ADMIN_PASSWORD")
                                  or os.getenv("ANTIGENT_JENKINS_ADMIN_PASSWORD") or None)
        
        return cls(
            cicd_goat_dir=cicd_goat_dir,
            defense_plane_dir=defense_plane_dir,
            run_dir=run_dir,
            attacker_model=attacker_model,
            defender_model=defender_model,
            openai_attacker_key=openai_attacker_key,
            openai_defender_key=openai_defender_key,
            aws_bearer_token_bedrock=aws_bearer_token_bedrock,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            aws_region=aws_region,
            attacker_aws_bearer_token_bedrock=attacker_aws["BEARER_TOKEN_BEDROCK"],
            attacker_aws_access_key_id=attacker_aws["ACCESS_KEY_ID"],
            attacker_aws_secret_access_key=attacker_aws["SECRET_ACCESS_KEY"],
            attacker_aws_session_token=attacker_aws["SESSION_TOKEN"],
            share_defender_credentials=os.getenv("ATTACKER_SHARE_DEFENDER_CREDENTIALS") == "1",
            attacker_egress_extra_allow=os.getenv("ATTACKER_EGRESS_EXTRA_ALLOW", ""),
            attacker_egress_upstream_proxy=os.getenv("ATTACKER_EGRESS_UPSTREAM_PROXY", ""),
            attack_startup_timeout=attack_startup_timeout,
            defense_turn_timeout=defense_turn_timeout,
            attack_timeout=attack_timeout,
            console_port=console_port,
            jenkins_url=jenkins_url,
            jenkins_admin_user=jenkins_admin_user,
            jenkins_admin_password=jenkins_admin_password,
            run_id=run_id,
        )

