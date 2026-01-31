"""
Configuration centralisée pour Otori Monitoring.
Utilise pydantic-settings pour charger les variables d'environnement.
"""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration de l'application."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Application
    # ─────────────────────────────────────────────────────────────────────────
    APP_NAME: str = "Otori Monitoring"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = False
    ENVIRONMENT: Literal["development", "testing", "staging", "production"] = "development"

    # ─────────────────────────────────────────────────────────────────────────
    # API Server
    # ─────────────────────────────────────────────────────────────────────────
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_RELOAD: bool = True

    # ─────────────────────────────────────────────────────────────────────────
    # Database
    # ─────────────────────────────────────────────────────────────────────────
    # Format: postgresql://user:password@host:port/dbname
    # Pour SQLite local: sqlite:///./otori.db
    DATABASE_URL: str = "sqlite:///./otori.db"

    # Pool de connexions (ignoré pour SQLite)
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_TIMEOUT: int = 30

    # ─────────────────────────────────────────────────────────────────────────
    # GeoIP
    # ─────────────────────────────────────────────────────────────────────────
    GEOIP_ENABLED: bool = True
    GEOIP_DB_PATH: str = "data/GeoLite2-City.mmdb"

    # ─────────────────────────────────────────────────────────────────────────
    # Analytics Features
    # ─────────────────────────────────────────────────────────────────────────
    ANALYTICS_ENABLED: bool = True
    BOT_DETECTION_ENABLED: bool = True
    MITRE_MAPPING_ENABLED: bool = True
    SESSION_SCORING_ENABLED: bool = True

    # ─────────────────────────────────────────────────────────────────────────
    # KPIs
    # ─────────────────────────────────────────────────────────────────────────
    KPI_DEFAULT_WINDOW_HOURS: int = 24
    KPI_MAX_TOP_ITEMS: int = 10

    # ─────────────────────────────────────────────────────────────────────────
    # Logging
    # ─────────────────────────────────────────────────────────────────────────
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    LOG_FORMAT: str = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"

    @property
    def is_sqlite(self) -> bool:
        """Vérifie si on utilise SQLite."""
        return self.DATABASE_URL.startswith("sqlite")

    @property
    def is_postgres(self) -> bool:
        """Vérifie si on utilise PostgreSQL."""
        return self.DATABASE_URL.startswith("postgresql")


@lru_cache
def get_settings() -> Settings:
    """
    Récupère les settings (singleton caché).

    Returns:
        Settings: Instance des paramètres de configuration.
    """
    return Settings()


# Raccourci pour import facile
settings = get_settings()
