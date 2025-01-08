import os
from typing import Optional, Dict, Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from app.core.http.rest_client import RestClient
from fastapi import HTTPException, status


class EJBCAClient:

    _rest_client: RestClient

    def __init__(self, base_url: str, certificate_path: str, key_path: str):
        self.base_url = base_url
        self.cert = (
            certificate_path,
            key_path
        )

        # Validate that both certificate and key paths exist
        if not self.cert_path or not self.key_path:
            raise ValueError("Client certificate or key path not provided.")
        if not self._validate_file(self.cert_path):
            raise ValueError(f"Certificate file not found: {self.cert_path}")
        if not self._validate_file(self.key_path):
            raise ValueError(f"Key file not found: {self.key_path}")

        # Set up a session with retries
        self.session = requests.Session()
        retries = Retry(total=5, backoff_factor=0.1,
                        status_forcelist=[502, 503, 504])
        self.session.mount("https://", HTTPAdapter(max_retries=retries))

    def fetch_certificate(self, serial_number: str) -> dict:
        """
        Fetch the certificate by serial number from EJBCA.
        Returns the certificate data or raises an HTTPException if not found.
        """
        url = f"{self.base_url}/certificates/{serial_number}"

        try:
            response = self.session.get(url, cert=self.cert)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None
            else:
                raise HTTPException(
                    status_code=response.status_code,
                    detail=f"Error fetching certificate: {response.text}"
                )
        except requests.RequestException as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to connect to EJBCA: {str(e)}"
            )

    def _validate_file(self, file_path: str) -> bool:
        """Check if a given file path exists and is readable."""
        return os.path.isfile(file_path) and os.access(file_path, os.R_OK)
