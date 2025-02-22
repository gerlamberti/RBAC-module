import os
import yaml

def load_config(project_path):
    """Loads the correct config.yaml based on the ENV environment variable."""
    env = os.getenv("ENV")
    if not env:
        raise ValueError("ENV environment variable not set!")
    
    config_file = f"{project_path}/config.{env}.yaml"

    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Config file {config_file} not found!")

    with open(config_file, "r") as file:
        config = yaml.safe_load(file)

    return config

# Example usage (if running standalone)
if __name__ == "__main__":
    config = load_config()
    print(f"Loaded configuration for {os.getenv('ENV', 'local')}")
    print(config)
