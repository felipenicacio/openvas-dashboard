from pydantic_settings import BaseSettings
from pydantic import Field
from functools import lru_cache


class Settings(BaseSettings):
    # GVM
    gvm_host: str = "127.0.0.1"
    gvm_port: int = 9390
    gvm_username: str = "admin"
    gvm_password: str = "admin"
    gvm_socket_path: str = ""

    # App auth
    app_username: str = "admin"
    app_password: str = "changeme"
    jwt_secret: str = "dev-secret-change-in-production"
    jwt_expire_minutes: int = 480

    # Sync
    sync_interval_minutes: int = 30

    # Dados
    data_dir: str = "/opt/openvas-dashboard/data"

    # CORS
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    @property
    def cors_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",")]

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
