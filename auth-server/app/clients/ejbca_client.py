import os
from typing import Optional, Dict, Any
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from fastapi import HTTPException, status
from pydantic import BaseModel
from typing import Tuple

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
    def __init__(self, base_url: str, key_path: str, cert_password: str):
        self.base_url = base_url
        self.key_path = key_path
        self.cert_password = cert_password

        # Validate that both certificate and key paths exist
        if not self.key_path:
            raise ValueError("Client certificate or key path not provided.")
        if not self._validate_file(self.key_path):
            raise ValueError(f"Key file not found: {self.key_path}")

        # Set up a session with retries
        self.session = requests.Session()
        retries = Retry(total=5, backoff_factor=0.1,
                        status_forcelist=[502, 503, 504])
        self.session.mount("https://", HTTPAdapter(max_retries=retries))

        # Define the function to log request/response details
        def log_request(response, *args, **kwargs):
            print(f"Request URL: {response.request.url}")
            print(f"Request Method: {response.request.method}")
            print(f"Request Headers: {response.request.headers}")
            print(f"Request Body: {response.request.body}")
            print(f"Response Status: {response.status_code}")
            print(f"Response Headers: {response.headers}")
            print(f"Response Body: {response.text}")
            return response

        self.session.hooks['response'] = [log_request]

    

    def get_revocation_status(self, issuer_dn: str, cert_serial: str) -> Tuple[RevocationStatus, object]:
        """
        Get the revocation status of a certificate by its serial number.
        :param issuer_dn: The DN of the certificate issuer
        :param cert_serial: The serial number of the certificate
        :return: A dictionary containing the revocation status information.
        """
        url = f"{self.base_url}/ejbca/ejbca-rest-api/v1/certificate/{issuer_dn}/{cert_serial}/revocationstatus"

        try:
            response = self.session.get(
                url,
                cert=(self.key_path, self.cert_password),  # Using the client certificate and password
                verify=False  # Disable SSL verification for testing (set to True for production)
            )

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
                return None, HTTPException(
                    status_code=response.status_code,
                    detail=f"Error fetching revocation status: {response.text}"
                )

        except requests.RequestException as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to connect to EJBCA for revocation status: {str(e)}"
            )

    def _validate_file(self, file_path: str) -> bool:
        """Check if a given file path exists and is readable."""
        return os.path.isfile(file_path) and os.access(file_path, os.R_OK)


if __name__ == "__main__":
    # Set up the EJBCAClient
    client = EJBCAClient(
        base_url="https://localhost:8443",  # Replace with your actual EJBCA server URL
        key_path="../../../certs/certificate.pem",  # Path to the .p12 file
        cert_password="../../../certs/private_key_no_passphrase.key"  # Password for the certificate
    )

    # Example data for issuer_dn and certificate serial number
    issuer_dn = "UID=c-CEJHfOUpRPS3Ms3gWyMJqCax3aoXmCwu,CN=ManagementCA,O=Example%20CA,C=SE"
    cert_serial_1 = "19F25BF2ADA9D577BCC1B1CF204CBD8FE5CE0093"
    cert_serial = "6e5d703375a5ad8e2132ab0d563a1c34bbd4c534"

    # Fetch the revocation status
    revocation_status, error = client.get_revocation_status(issuer_dn, cert_serial)
    if error is not None:
        print ("Error", error)
    else:
        if revocation_status.revoked == True:
            print("Esta revocado")
        else:
            print("No lo esta")

        print("Revocation Status:", revocation_status)
