"""
app/config.py — Application configuration using Pydantic Settings.

Reads from environment variables or .env file.
"""
from pathlib import Path
from typing import Union
from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # General
    app_name: str = "CyberSec AI - Threat Detection"
    app_version: str = "1.0.0"
    environment: str = "development"
    debug: bool = True
    secret_key: str = "local-test-123"

    # Database
    database_url: str = "sqlite:///./cybersec_ai.db"

    # File Upload
    max_upload_mb: int = 10
    upload_folder: str = "static/uploads"

    # ML Artifacts
    artifacts_dir: str = "artifacts"

    # API
    api_prefix: str = "/api/v1"
    cors_origins: Union[str, list[str]] = ["http://localhost:8501", "http://127.0.0.1:8501", "http://localhost:3000"]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, list[str]]) -> list[str]:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                import json
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [i.strip() for i in v.split(",") if i.strip()]
        return v

    # ML Model Settings
    isolation_forest_contamination: float = 0.1  # Approx fraction of anomalies
    random_forest_n_estimators: int = 100
    random_seed: int = 42
    test_split_size: float = 0.2

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


# Singleton instance
settings = Settings()

# Derived paths
BASE_DIR = Path(__file__).parent.parent
ARTIFACTS_PATH = BASE_DIR / settings.artifacts_dir
DATA_SAMPLE_PATH = BASE_DIR / "data" / "sample"
UPLOAD_PATH = BASE_DIR / settings.upload_folder

# Ensure directories exist
ARTIFACTS_PATH.mkdir(parents=True, exist_ok=True)
DATA_SAMPLE_PATH.mkdir(parents=True, exist_ok=True)
UPLOAD_PATH.mkdir(parents=True, exist_ok=True)
