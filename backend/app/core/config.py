"""
Configuration management for Security Management Platform
"""
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import Field
import os


class Settings(BaseSettings):
    """Application settings"""
    
    # Environment
    ENVIRONMENT: str = Field(default="development", env="ENVIRONMENT")
    DEBUG: bool = Field(default=True, env="DEBUG")
    LOG_LEVEL: str = Field(default="info", env="LOG_LEVEL")
    
    # API Configuration
    API_HOST: str = Field(default="0.0.0.0", env="API_HOST")
    API_PORT: int = Field(default=8000, env="API_PORT")
    API_CORS_ORIGINS: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:5173", "http://localhost:5000"],
        env="API_CORS_ORIGINS"
    )
    
    # LLM Configuration
    LLM_MODEL_NAME: str = Field(default="microsoft/DialoGPT-medium", env="LLM_MODEL_NAME")
    LLM_DEVICE: str = Field(default="auto", env="LLM_DEVICE")
    LLM_MAX_LENGTH: int = Field(default=512, env="LLM_MAX_LENGTH")
    LLM_TEMPERATURE: float = Field(default=0.7, env="LLM_TEMPERATURE")
    LLM_TOP_P: float = Field(default=0.9, env="LLM_TOP_P")
    
    # Groq Configuration
    GROQ_API_KEY: Optional[str] = Field(default=None, env="GROQ_API_KEY")
    GROQ_MODEL: str = Field(default="llama3-70b-8192", env="GROQ_MODEL")
    
    # Data Storage
    DATA_DIR: str = Field(default="data", env="DATA_DIR")
    LOGS_DIR: str = Field(default="logs", env="LOGS_DIR")
    
    # External APIs
    NVD_API_KEY: Optional[str] = Field(default=None, env="NVD_API_KEY")
    SHODAN_API_KEY: Optional[str] = Field(default=None, env="SHODAN_API_KEY")
    GITHUB_TOKEN: Optional[str] = Field(default=None, env="GITHUB_TOKEN")
    JIRA_URL: Optional[str] = Field(default=None, env="JIRA_URL")
    JIRA_USERNAME: Optional[str] = Field(default=None, env="JIRA_USERNAME")
    JIRA_PASSWORD: Optional[str] = Field(default=None, env="JIRA_PASSWORD")
    
    # Email Configuration
    SMTP_SERVER: str = Field(default="smtp.gmail.com", env="SMTP_SERVER")
    SMTP_PORT: int = Field(default=587, env="SMTP_PORT")
    SMTP_USERNAME: Optional[str] = Field(default=None, env="SMTP_USERNAME")
    SMTP_PASSWORD: Optional[str] = Field(default=None, env="SMTP_PASSWORD")
    EMAIL_FROM: str = Field(default="security@company.com", env="EMAIL_FROM")
    
    # Vulnerability Scanner Configuration
    OPENVAS_HOST: str = Field(default="localhost", env="OPENVAS_HOST")
    OPENVAS_PORT: int = Field(default=9390, env="OPENVAS_PORT")
    OPENVAS_USERNAME: str = Field(default="admin", env="OPENVAS_USERNAME")
    OPENVAS_PASSWORD: str = Field(default="admin", env="OPENVAS_PASSWORD")
    
    NESSUS_HOST: str = Field(default="localhost", env="NESSUS_HOST")
    NESSUS_PORT: int = Field(default=8834, env="NESSUS_PORT")
    NESSUS_USERNAME: str = Field(default="admin", env="NESSUS_USERNAME")
    NESSUS_PASSWORD: str = Field(default="admin", env="NESSUS_PASSWORD")
    
    # Security
    SECRET_KEY: str = Field(default="your-secret-key-here-change-in-production", env="SECRET_KEY")
    ALGORITHM: str = Field(default="HS256", env="ALGORITHM")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    
    class Config:
        env_file = ".env"
        case_sensitive = True


# Global settings instance
settings = Settings() 