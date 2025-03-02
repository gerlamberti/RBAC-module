import logging
from typing import Optional, Tuple

from app.domain.entities.authorized_keys import AuthorizedKeysBuilder
from app.domain.repositories.certificate_repository import \
    CertificateRepository
from pydantic import BaseModel


class AuthResponse(BaseModel):
    allowed: bool
    authorized_keys_entry: Optional[str] = None


class AuthenticateService:
    def __init__(self,
                 certificate_repository: CertificateRepository,
                 authorized_keys_builder: AuthorizedKeysBuilder,
                 logger: logging.Logger = logging.getLogger(__name__)):
        self.certificate_repository = certificate_repository
        self.authorized_keys_builder = authorized_keys_builder
        self.logger = logger

    def authenticate(self, serial_id: str, username: str) -> Tuple[AuthResponse, dict]:
        isRevoked, err = self.certificate_repository.is_revoked(serial_id)
        if err:
            return None, {"error": "is_revoked call failed", "detail": err}
        if isRevoked:
            return AuthResponse(allowed=False), None

        certificate, err = self.certificate_repository.get_certificate(
            serial_id)

        if err:
            return None, {"error": "get_certificate failed", "detail": err}

        if certificate.is_expired():
            self.logger.info("Certificate is expired")
            return AuthResponse(allowed=False), None
        self.logger.debug("Certificate role: %s",
                          certificate.subject_components["role"])
        self.logger.debug("Username: %s", username)
        if certificate.subject_components["role"] != username:
            return AuthResponse(allowed=False), None
        try:
            authorized_keys_entry = self.authorized_keys_builder.build(
                certificate.subject_components["emailAddress"],
                certificate.subject_components["CN"],
                certificate.subject_components["role"],
                certificate.public_key
            )
        except Exception as e:
            return None, {"error": "authorized_keys_builder failed", "detail": str(e)}
        return AuthResponse(allowed=True, authorized_keys_entry=authorized_keys_entry), None
