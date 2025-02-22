from typing import Optional, Tuple

from pydantic import BaseModel

from app.domain.repositories.certificate_repository import CertificateRepository

class AuthResponse(BaseModel):
    allowed: bool
    public_key: Optional[str] = None



class AuthenticateService:
    def __init__(self, certificate_repository: CertificateRepository):
        self.certificate_repository = certificate_repository

    def authenticate(self, serial_id: str) -> Tuple[AuthResponse, dict]:
        isRevoked, err = self.certificate_repository.is_revoked(serial_id)
        if err:
            return None, {"error": "is_revoked call failed", "detail": err}
        if isRevoked:
            return AuthResponse(allowed=False), None

        certificate, err = self.certificate_repository.get_certificate(serial_id)

        if err:
            return None, {"error": "get_certificate failed", "detail": err}

        if certificate.is_expired():
            print("Certificate is expired")
            return AuthResponse(allowed=False), None

        return AuthResponse(allowed=True, public_key=certificate.public_key.pem_key), None
