"""Runtime configuration.

All values are overridable via environment variables (prefix ``KITSUNOX_``) or a local
``.env`` file. See ``.env.example``.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="KITSUNOX_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Storage ---
    data_dir: Path = Path("data")
    db_url: str = "sqlite:///data/kitsunox.db"

    # --- npm endpoints ---
    replicate_base_url: str = "https://replicate.npmjs.com/registry"
    registry_base_url: str = "https://registry.npmjs.org"
    downloads_base_url: str = "https://api.npmjs.org"
    deps_dev_base_url: str = "https://api.deps.dev"

    # --- feed consumer ---
    changes_page_limit: int = Field(default=1000, ge=1, le=10_000)
    poll_interval_seconds: float = 15.0
    # "now"  -> start near the current update_seq
    # "now-N" -> start N sequence units before the current update_seq
    # "0"    -> full historical crawl
    feed_start: str = "now"
    # Opt-in header required by the post-2025 replication API.
    replication_opt_in: bool = True

    # --- HTTP ---
    http_timeout_seconds: float = 30.0
    user_agent: str = "kitsunox/0.1 (+https://github.com/TheStair/kitsunox)"

    # --- threat intel ---
    osv_query_url: str = "https://api.osv.dev/v1/query"
    malicious_packages_repo: str = "https://github.com/ossf/malicious-packages"

    @property
    def tarball_cache_dir(self) -> Path:
        return self.data_dir / "tarball-cache"

    @property
    def intel_mirror_dir(self) -> Path:
        return self.data_dir / "intel-mirror"

    def ensure_dirs(self) -> None:
        for p in (self.data_dir, self.tarball_cache_dir, self.intel_mirror_dir):
            p.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()
