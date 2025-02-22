import logging
import logging.config
from typing import Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from fastapi import HTTPException, status
from pydantic import BaseModel
import sys
raise Exception(sys.version)


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


class AuthResponse(BaseModel):
    """
    A structured representation of the authentication response.
    """
    allowed: bool
    public_key: Optional[str] = None


class AuthServerClient:
    def __init__(self, base_url: str, logger: logging.Logger):
        """
        Initialize the AuthServerClient with the provided base URL and logger.

        :param base_url: The base URL of the auth server (e.g., "https://authserver.example.com/api")
        :param logger: A logger instance to log messages.
        """
        # Remove any trailing slash to ensure proper URL concatenation
        self.base_url = base_url.rstrip("/")
        self.logger = logger

        # Set up a requests session with retries
        self.session = requests.Session()
        retries = Retry(total=5, backoff_factor=0.1, status_forcelist=[502, 503, 504])
        self.session.mount("https://", HTTPAdapter(max_retries=retries))
        self.logger.debug(
            "AuthServerClient initialized with base_url: %s", self.base_url
        )

    def authenticate(self, serial_id: str) -> AuthResponse:
        """
        Call the auth server endpoint to validate a certificate by its serial_id.

        :param serial_id: The certificate's serial identifier.
        :return: An AuthResponse object representing the authentication result.
        """
        url = f"{self.base_url}/api/v1/certificate/{serial_id}/validate"
        self.logger.debug("Calling auth server endpoint: %s", url)
        try:
            response = self.session.get(url)
            self.logger.debug(
                "Received response with status code: %s", response.status_code
            )
        except requests.RequestException as e:
            self.logger.exception(
                "Error calling auth server endpoint for serial: %s", serial_id
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error connecting to auth server: {str(e)}",
            )

        if response.status_code == 200:
            self.logger.info("Certificate %s validated successfully.", serial_id)
            data = response.json()
            return AuthResponse(**data)
        elif response.status_code in (400, 403):
            self.logger.error(
                "Certificate %s validation failed with status code: %s",
                serial_id,
                response.status_code,
            )
            data = (
                response.json()
                if response.content
                else {"allowed": False, "public_key": None}
            )
            return AuthResponse(**data)
        elif response.status_code == 500:
            self.logger.error(
                "Internal server error from auth server for certificate %s", serial_id
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error in auth server.",
            )
        else:
            self.logger.error(
                "Unexpected response code %s from auth server for certificate %s",
                response.status_code,
                serial_id,
            )
            raise HTTPException(
                status_code=response.status_code,
                detail="Unexpected response from auth server.",
            )


init_logging()
logger = logging.getLogger(__name__)
logger.info("Application started")
auth_client = AuthServerClient(base_url="http://localhost:8888/", logger=logger)
#
# Duplicates pam_permit.c
#
DEFAULT_USER_ID = "abc_sebas"


def pam_sm_authenticate(pamh, flags, argv):
    try:
        user = pamh.get_user(None)
        if user is None:
            logger.error("User is None")
            return pamh.PAM_USER_UNKNOWN
        # f = open(f"/home/{user}/.ssh/authorized_keys","w+")
        f = open("/home/" + user + "/.ssh/authorized_keys", "w+")
        if f is None:
            logger.error("File is None")
            return pamh.PAM_USER_UNKNOWN

        msg = pamh.Message(
            pamh.PAM_PROMPT_ECHO_ON, "Ingrese el serial_id de su certificado: "
        )
        resp = pamh.conversation(msg)
        serial_id = resp.resp
        if serial_id is None:
            return pamh.PAM_USER_UNKNOWN
        pamh.conversation(
            pamh.Message(
                pamh.PAM_TEXT_INFO, "Buscando certificado con serial_id: " + serial_id
            )
        )

        auth_response = auth_client.authenticate(serial_id)

        if not auth_response.allowed:
            logger.error("Certificate %s is not allowed.", serial_id)
            return pamh.PAM_AUTH_ERR

        pamh.conversation(
            pamh.Message(
                pamh.PAM_TEXT_INFO,
                "Encontrado :) Anadida clave publica a authorized_keys",
            )
        )

        f.write(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHDzwbYUjqoUwpfjHvBmOAsDqJKAl+hqVEkUvqC5dYUt bruno178pm@gmail.com"
        )
        f.close()
        f2 = open("/tmp/enviroment_test", "w")
        f2.write("\nuser:")
        f2.write(user)
        f2.write("Tiene USERNAME:")
        f2.write(str(pamh.env.has_key("USERNAME")))
        f2.write("\nTiene EJBCA:")
        f2.write(str(pamh.env.has_key("EJBCA")))
        f2.write("\nTiene HOME:")
        f2.write(str(pamh.env.has_key("HOME")))
        f2.write(" Tiene EJBCA_USER_ID:")
        f2.write(str(pamh.env.has_key("EJBCA_USER_ID")))
        f2.write(" \n flags ")
        f2.write(str(flags))
        f2.write(" \n argv ")
        f2.write(str(argv))
        f2.close()
        # print(len(pamh.env.items))
        # for item in pamh.env.values:
        #  f2 = open("/tmp/enviroment_test","w")
        #  f2.write(item)
        #  f2.close()
        #  print(item)
    except Exception as e:
        f3 = open("/tmp/error", "w")
        f3.write(str(e))
        f3.close()
        return pamh.PAM_USER_UNKNOWN

    return pamh.PAM_SUCCESS
    # return pamh.PAM_SUCCESS


def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_acct_mgmt(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_open_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_close_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_chauthtok(pamh, flags, argv):
    return pamh.PAM_SUCCESS


if __name__ == "__main__":
     # Instantiate the client with a sample base URL
    client = AuthServerClient(base_url="http://localhost:8888/", logger=logger)
    
    # Example call to the authenticate method
    try:
        auth_result = client.authenticate("1eb97febf0e01bb7f1891cbd837087af3064740b")
        logger.info("Authentication result: %s", auth_result)
    except HTTPException as exc:
        logger.error("Authentication failed: %s", exc.detail)
