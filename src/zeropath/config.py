"""
Configuration management using Pydantic Settings.
"""

from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings with support for environment variables."""

    # Paths
    contracts_dir: Path = Path("contracts")
    output_dir: Path = Path("output")
    
    # Slither configuration
    solc_version: Optional[str] = None
    solc_remappings: Optional[dict[str, str]] = None
    
    # Neo4j configuration
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_username: str = "neo4j"
    neo4j_password: str = "password"
    neo4j_database: str = "neo4j"
    neo4j_enabled: bool = True
    
    # Analysis settings
    extract_storage_layout: bool = True
    extract_asset_flows: bool = True
    calculate_complexity: bool = True
    
    # Logging
    log_level: str = "INFO"
    log_file: Optional[Path] = None
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


def get_settings() -> Settings:
    """Get global settings instance."""
    return Settings()
