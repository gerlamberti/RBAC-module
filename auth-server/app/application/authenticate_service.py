from typing import Optional, Tuple

from app.domain.repositories.certificate_repository import CertificateRepository


class AuthResponse:
    def __init__(self, allowed: bool, public_key: Optional[str] = None):
        self.allowed = allowed
        self.public_key = public_key


class AuthenticateService:
    def __init__(self, certificate_repository: CertificateRepository):
        self.certificate_repository = certificate_repository

    def authenticate(self, serial_id: str) -> Tuple[AuthResponse, dict]:
        isRevoked, err = self.certificate_repository.is_revoked(serial_id)
        if err:
            return None, f"is_revoked error: {err}"
        if isRevoked:
            return AuthResponse(allowed=False), None

        certificate, err = self.certificate_repository.get_certificate(serial_id)

        if err:
            return None, f"get_certificate error: {err}"

        if certificate.is_expired():
            return AuthResponse(allowed=False), None

        return AuthResponse(allowed=True, public_key=certificate.public_key), None
