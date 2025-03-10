from functools import lru_cache
import os

from app.core.config.load_config import load_config


@lru_cache
def get_config() -> dict:
    config, err = load_config(project_path=os.getenv("PROJECT_PATH"))
    if err:
        raise err
    return config
