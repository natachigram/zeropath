"""
Configuration management using Pydantic Settings.

All values are read from environment variables or a .env file, with
safe defaults for local development. Override via environment for CI/CD.
"""

from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application-wide settings.

    Environment variable names match field names, uppercased.
    Example: ZEROPATH_NEO4J_URI=bolt://myhost:7687
    """

    model_config = SettingsConfigDict(
        env_prefix="ZEROPATH_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Paths ---
    contracts_dir: Path = Path("contracts")
    output_dir: Path = Path("output")

    # --- Slither / compiler ---
    solc_version: Optional[str] = None
    solc_remappings: Optional[str] = None  # Comma-separated key=value pairs

    # --- Neo4j ---
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_username: str = "neo4j"
    neo4j_password: str = "password"
    neo4j_database: str = "neo4j"
    neo4j_enabled: bool = True

    # --- Analysis toggles ---
    extract_storage_layout: bool = True
    extract_asset_flows: bool = True
    extract_events: bool = True
    detect_proxies: bool = True

    # --- Performance ---
    max_workers: int = 4  # multiprocessing worker count for parallel file analysis
    analysis_timeout_seconds: int = 120  # per-contract Slither timeout

    # --- GitHub ingestion ---
    github_token: Optional[str] = None  # Personal access token for private repos
    github_clone_dir: Path = Path("/tmp/zeropath_repos")

    # --- Heimdall (bytecode decompiler fallback) ---
    heimdall_bin: Optional[Path] = None  # Path to heimdall binary, None = disabled
    heimdall_timeout_seconds: int = 60

    # --- Logging ---
    log_level: str = "INFO"
    log_file: Optional[Path] = None


def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
