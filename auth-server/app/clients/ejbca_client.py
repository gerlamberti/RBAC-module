import logging
import os
from typing import Dict, List, Optional, Tuple

import requests
from pydantic import BaseModel
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class RevocationStatus(BaseModel):
    """
    A structured representation of the certificate revocation status.
    """
    issuer_dn: Optional[str]
    serial_number: Optional[str]
    revocation_reason: Optional[str]
    revocation_date: Optional[str]
    message: Optional[str]
    revoked: Optional[bool]


class EJBCAClient:
    """ A client to interact with the EJBCA REST API. """

    def __init__(self, base_url: str,
                 key_path: str,
                 cert_password: str,
                 logger: logging.Logger = logging.getLogger(__name__),
                 session: requests.Session = requests.Session()):
        self.logger = logger
        self.logger.name = __name__

        self.base_url = base_url
        self.key_path = key_path
        self.cert_password = cert_password

        # Validate that both certificate and key paths exist
        if not self.key_path:
            raise ValueError("Client certificate or key path not provided.")
        if not self._validate_file(self.key_path):
            raise ValueError(f"Key file not found: {self.key_path}")

        # Set up a session with retries
        self.session = session
        retries = Retry(total=5, backoff_factor=0.1,
                        status_forcelist=[502, 503, 504])

        self.session.cert = (self.key_path, self.cert_password)
        self.session.verify = False

        self.session.mount("https://", HTTPAdapter(max_retries=retries))

    def get_revocation_status(self, issuer_dn: str, cert_serial: str) -> Tuple[RevocationStatus, object]:
        """
        Get the revocation status of a certificate by its serial number.
        :param issuer_dn: The DN of the certificate issuer
        :param cert_serial: The serial number of the certificate
        :return: A dictionary containing the revocation status information.
        """
        url = f'{self.base_url}/v1/certificate/{issuer_dn}/{cert_serial}/revocationstatus'
        self.logger.info(f'Attemping to connect to {url}')
        try:
            response = self.session.get(url)

            if response.status_code == 200:
                data = response.json()
                return RevocationStatus(
                    issuer_dn=data.get("issuer_dn"),
                    serial_number=data.get("serial_number"),
                    revocation_reason=data.get("revocation_reason"),
                    revocation_date=data.get("revocation_date"),
                    message=data.get("message"),
                    revoked=data.get("revoked")
                ), None
            elif response.status_code == 404:
                return None, {"detail": f"Certificate with serial {cert_serial} not found"}
            else:
                return None, {"error": response.text}
        except requests.RequestException as e:
            return None, {"error": str(e), "url": url}

    def search(self, max_results: int, criteria: List[Dict]) -> Tuple[Dict, object]:
        """
        Searches for certificates based on the given criteria.

        Args:
            max_results (int): Maximum number of results to return.
            criteria (List[Dict]): List of search criteria dictionaries. Each dictionary should include:
                - property: (str) Search property (e.g., QUERY, STATUS, etc.)
                - value: (str) Value for the property.
                - operation: (str) Operation type (e.g., EQUAL, LIKE, BEFORE, AFTER).

        Returns:
            Dict: Response from the EJBCA API.
        """
        url = f"{self.base_url}/v1/certificate/search"
        body = {
            "max_number_of_results": max_results,
            "criteria": criteria
        }

        try:
            response = self.session.post(url, json=body)
            if response.status_code == 200:
                return response.json(), None
            else:
                return None, {"error": response.text, "url": url, "error_code": response.status_code}
        except requests.exceptions.RequestException as e:
            return None, {"error": str(e), "url": url}

    def _validate_file(self, file_path: str) -> bool:
        """Check if a given file path exists and is readable."""
        return os.path.isfile(file_path) and os.access(file_path, os.R_OK)
