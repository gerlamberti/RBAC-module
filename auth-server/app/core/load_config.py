"""Configuration loader module for the authentication server."""

import os
from typing import Tuple
import yaml


def load_config(project_path: str) -> Tuple[dict, Exception]:
    """Loads the correct config.yaml based on the ENV environment variable."""
    env = os.getenv("ENV")
    if not env:
        return None, ValueError("ENV environment variable not set!")

    config_file = f"{project_path}/config/config.{env}.yaml"

    if not os.path.exists(config_file):
        return None, FileNotFoundError(f"Config file {config_file} not found!")

    try:
        with open(config_file, "r", encoding="utf-8") as file:
            config = yaml.safe_load(file)
        return config, None
    except (IOError, yaml.YAMLError) as e:
        return None, e


# Example usage (if running standalone)
if __name__ == "__main__":
    config, err = load_config(project_path="/Users/bruno/Programacion/ejbca-tesis/auth-server")
    print(f"Loaded configuration for {os.getenv('ENV', 'local')}")
    if err:
        print(f"Error loading configuration: {err}")
    else:
        print(config)
