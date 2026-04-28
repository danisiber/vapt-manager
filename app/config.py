from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    APP_NAME: str = "VAPT Manager — Bank Kalbar"
    SECRET_KEY: str = "bank-kalbar-vapt-secret-key-2026-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480

    class Config:
        env_file = ".env"

@lru_cache()
def get_settings():
    return Settings()
