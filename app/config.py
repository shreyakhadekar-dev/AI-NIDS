from pydantic_settings import BaseSettings
class Settings(BaseSettings):
    app_name: str = "NetSentinel AI Pro"
    database_url: str = "sqlite:///./netsentinel.db"
    secret_key: str = "change-this-in-production"
    upload_dir: str = "uploads"
    report_dir: str = "reports"
    max_upload_mb: int = 25
settings = Settings()
