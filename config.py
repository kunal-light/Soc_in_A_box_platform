"""Centralized configuration for SOC-in-a-Box.

Secrets are read from environment variables and are never committed to source.
"""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = os.getenv("DB_PORT", "5432")
    DB_NAME = os.getenv("DB_NAME", "ioc_database")
    DB_USER = os.getenv("DB_USER", "postgres")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")

    OTX_API_KEY = os.getenv("OTX_API_KEY", "")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

   

    SECRET_KEY = os.getenv(
        "FLASK_SECRET_KEY",
        "change-this-in-production"
    )

    ADMIN_USERNAME = os.getenv(
        "ADMIN_USERNAME",
        "admin"
    )

    ADMIN_PASSWORD_HASH = os.getenv(
        "ADMIN_PASSWORD_HASH",
        "scrypt:32768:8:1$EFffIfKsNNWFFA1x$426c303f8195c3ecee0e8416c164ca4f70ef1e4f9f62e37ef613eb18d04a4b3ff67a837ca5a2fd800e192fa6225335e87937525fb9ee0209b963947d7a14bc07"
    )

    DEBUG = os.getenv(
        "FLASK_DEBUG",
        "true"
    ).lower() in ("1", "true", "yes")

    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

    
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")