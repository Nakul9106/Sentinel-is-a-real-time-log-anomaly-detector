"""Configuration management for Sentinel.

Provides YAML loading, environment variable lookups, and CLI argument overrides
using typed dataclasses and pathlib.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
import yaml


@dataclass
class SentinelConfig:
    """Sentinel runtime and training configuration."""

    # Paths
    log_file: Path = field(default_factory=lambda: Path("data/app.log"))
    model_path: Path = field(default_factory=lambda: Path("models/sentinel_model.joblib"))
    config_path: Optional[Path] = None

    # Anomaly Detection Parameters
    # Severity score threshold: 0.0 (normal) to 1.0 (severe anomaly)
    threshold: float = 0.65
    raw_threshold: float = 0.0
    model_type: str = "isolation_forest"  # "isolation_forest" or "one_class_svm"
    contamination: float = 0.01

    # Alerting Parameters
    webhook_env_var: str = "SLACK_WEBHOOK_URL"
    webhook_url: Optional[str] = None
    discord_webhook_url: Optional[str] = None
    rate_limit_seconds: float = 5.0
    dedup_window_seconds: float = 30.0
    max_retries: int = 3
    webhook_timeout: float = 4.0
    dry_run: bool = True

    # Ingestion & Runtime Parameters
    poll_interval: float = 0.1
    batch_size: int = 1
    log_level: str = "INFO"
    from_start: bool = False

    def resolve_webhook_url(self) -> Optional[str]:
        """Resolves the active webhook URL from environment variable or direct config."""
        env_url = os.environ.get(self.webhook_env_var, "").strip()
        if env_url:
            return env_url
        if self.webhook_url and self.webhook_url.strip():
            return self.webhook_url.strip()
        return None

    def resolve_discord_webhook_url(self) -> Optional[str]:
        """Resolves the active Discord webhook URL from environment or config."""
        env_url = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
        if env_url:
            return env_url
        if self.discord_webhook_url and self.discord_webhook_url.strip():
            return self.discord_webhook_url.strip()
        return None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SentinelConfig:
        """Create a SentinelConfig instance from a dictionary, casting paths appropriately."""
        clean_data = dict(data)

        if "log_file" in clean_data and clean_data["log_file"]:
            clean_data["log_file"] = Path(clean_data["log_file"])
        if "model_path" in clean_data and clean_data["model_path"]:
            clean_data["model_path"] = Path(clean_data["model_path"])
        if "config_path" in clean_data and clean_data["config_path"]:
            clean_data["config_path"] = Path(clean_data["config_path"])

        # Filter out unknown keys to allow forward compatibility
        valid_fields = set(cls.__dataclass_fields__.keys())
        filtered = {k: v for k, v in clean_data.items() if k in valid_fields and v is not None}
        return cls(**filtered)


def load_config(
    config_file: Optional[Path | str] = None,
    cli_overrides: Optional[dict[str, Any]] = None,
) -> SentinelConfig:
    """Loads configuration from YAML file, merges with environment and CLI arguments.

    Priority order:
    1. CLI overrides (highest)
    2. Environment variables (e.g. SENTINEL_LOG_FILE, SENTINEL_THRESHOLD)
    3. YAML configuration file
    4. Default SentinelConfig values (lowest)
    """
    config_dict: dict[str, Any] = {}
    resolved_config_path: Optional[Path] = None

    # 1. Determine config file path
    if config_file:
        resolved_config_path = Path(config_file)
    elif os.environ.get("SENTINEL_CONFIG"):
        resolved_config_path = Path(os.environ["SENTINEL_CONFIG"])
    else:
        default_yaml = Path("config.yaml")
        if default_yaml.is_file():
            resolved_config_path = default_yaml

    # 2. Load YAML if file exists
    if resolved_config_path and resolved_config_path.is_file():
        try:
            with open(resolved_config_path, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    config_dict.update(loaded)
        except Exception as e:
            # Fall back gracefully with a warning
            print(f"[WARN] Failed to parse config file '{resolved_config_path}': {e}. Using defaults.")

    # 3. Apply Environment Variable overrides
    env_mappings = {
        "SENTINEL_LOG_FILE": ("log_file", lambda v: Path(v)),
        "SENTINEL_MODEL_PATH": ("model_path", lambda v: Path(v)),
        "SENTINEL_THRESHOLD": ("threshold", float),
        "SENTINEL_RATE_LIMIT": ("rate_limit_seconds", float),
        "SENTINEL_LOG_LEVEL": ("log_level", str),
        "SENTINEL_DRY_RUN": ("dry_run", lambda v: v.lower() in ("1", "true", "yes")),
        "SLACK_WEBHOOK_URL": ("webhook_url", str),
        "DISCORD_WEBHOOK_URL": ("discord_webhook_url", str),
    }

    for env_var, (cfg_key, converter) in env_mappings.items():
        if env_var in os.environ and os.environ[env_var].strip():
            try:
                config_dict[cfg_key] = converter(os.environ[env_var].strip())
            except (ValueError, TypeError):
                pass

    # 4. Apply CLI overrides
    if cli_overrides:
        for key, val in cli_overrides.items():
            if val is not None:
                config_dict[key] = val

    if resolved_config_path:
        config_dict["config_path"] = resolved_config_path

    return SentinelConfig.from_dict(config_dict)
