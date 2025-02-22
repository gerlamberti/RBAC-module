# auth_server_client.py
import logging
from typing import Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from fastapi import HTTPException, status
from pydantic import BaseModel

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
        self.logger.debug("AuthServerClient initialized with base_url: %s", self.base_url)

    def authenticate(self, serial_id: str) -> AuthResponse:
        """
        Call the auth server endpoint to validate a certificate by its serial_id.
        
        :param serial_id: The certificate's serial identifier.
        :return: An AuthResponse object representing the authentication result.
        """
        url = f"{self.base_url}/certificate/{serial_id}/validate"
        self.logger.debug("Calling auth server endpoint: %s", url)
        try:
            response = self.session.get(url)
            self.logger.debug("Received response with status code: %s", response.status_code)
        except requests.RequestException as e:
            self.logger.exception("Error calling auth server endpoint for serial: %s", serial_id)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Error connecting to auth server: {str(e)}"
            )
        
        if response.status_code == 200:
            self.logger.info("Certificate %s validated successfully.", serial_id)
            data = response.json()
            return AuthResponse(**data)
        elif response.status_code in (400, 403):
            self.logger.error("Certificate %s validation failed with status code: %s", serial_id, response.status_code)
            data = response.json() if response.content else {"allowed": False, "public_key": None}
            return AuthResponse(**data)
        elif response.status_code == 500:
            self.logger.error("Internal server error from auth server for certificate %s", serial_id)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error in auth server."
            )
        else:
            self.logger.error("Unexpected response code %s from auth server for certificate %s", response.status_code, serial_id)
            raise HTTPException(
                status_code=response.status_code,
                detail="Unexpected response from auth server."
            )

# Example usage (for testing purposes)
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    test_logger = logging.getLogger("AuthServerClientTest")
    
    # Instantiate the client with a sample base URL
    client = AuthServerClient(base_url="https://authserver.example.com/api", logger=test_logger)
    
    # Example call to the authenticate method
    try:
        auth_result = client.authenticate("sample_serial_id")
        test_logger.info("Authentication result: %s", auth_result)
    except HTTPException as exc:
        test_logger.error("Authentication failed: %s", exc.detail)
