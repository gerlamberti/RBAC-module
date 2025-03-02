import base64
from typing import Callable
from OpenSSL import crypto
from datetime import datetime, timezone

from app.domain.entities.certificate import Certificate, SerialNumber
from app.domain.entities.x509_public_key import X509PublicKey


class CertificateDecoder:
    def __init__(self):
        pass

    def from_raw(self, raw_certificate: str) -> Certificate:
        """
        Maps a raw certificate string to a Certificate entity.

        Args:
            raw_certificate (str): Base64 encoded certificate string.

        Returns:
            Certificate: A domain Certificate entity.
        """
        # Decode Base64
        decoded_cert = base64.b64decode(raw_certificate)
        certificate_header_label = b"-----BEGIN CERTIFICATE-----\n"
        certificate_footer_label = b"\n-----END CERTIFICATE-----"
        full_cert = certificate_header_label + decoded_cert + certificate_footer_label

        # Parse the certificate using OpenSSL
        try:
            x509 = crypto.load_certificate(crypto.FILETYPE_PEM, full_cert)
        except crypto.Error as e:
            raise ValueError("Invalid certificate format") from e

        # Extract fields
        serial_number = x509.get_serial_number()
        
        public_key = crypto.dump_publickey(
            crypto.FILETYPE_PEM, x509.get_pubkey()
        ).decode("utf-8")
        
        expiry_date = datetime.strptime(
            x509.get_notAfter().decode("utf-8"), "%Y%m%d%H%M%SZ"
        ).astimezone(timezone.utc)

        
        subject_components = x509.get_subject().get_components()
        subject_components_dict = {key.decode(): value.decode() for key, value in subject_components}

        # Create and return the Certificate entity
        return Certificate(
            serial_id=SerialNumber(serial_number),
            public_key=X509PublicKey(public_key),
            expiry_date=expiry_date,
            subject_components = subject_components_dict
        )
