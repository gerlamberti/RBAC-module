# logging_config.py
import logging
import logging.config
from app.core import load_config  # Assuming this returns a configuration dictionary

def init_logging():
    default_logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "default",
                "level": "DEBUG",
            },
            "file": {
                "class": "logging.FileHandler",
                "filename": "app.log",  # Ensure this path is writable
                "formatter": "default",
                "level": "DEBUG",
            },
        },
        "root": {
            "level": "DEBUG",
            "handlers": ["console", "file"],
        },
    }
    logging.config.dictConfig(default_logging_config)
