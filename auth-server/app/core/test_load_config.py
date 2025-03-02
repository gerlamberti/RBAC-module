import os
import tempfile
import pytest
import yaml

from app.core.load_config import load_config


@pytest.fixture
def config_dict():
    return {
        "ejbca": {
            "base_url": "https://ejbca-server.com",
            "certificate_path": "/path/to/certificate.pem",
            "cert_password": "password"
        }
    }


@pytest.fixture(autouse=True)
def get_config_file(config_dict):
    # convert dict to yaml
    valid_yaml = yaml.dump(config_dict)
    # generate temporary yaml file
    # create temp directory
    temp_dir = tempfile.mkdtemp()
    with tempfile.NamedTemporaryFile(delete=True,
                                     suffix=".yaml",
                                     dir=temp_dir) as temp_file:
        temp_file.write(valid_yaml.encode("utf-8"))
        yield temp_file.name


@pytest.mark.skip(reason="This test is not implemented yet")
def test_load_config(get_config_file):
    # configure env
    os.environ["ENV"] = "test"
    config, err = load_config(
        project_path=get_config_file)
    assert config is not None
    assert err is None
