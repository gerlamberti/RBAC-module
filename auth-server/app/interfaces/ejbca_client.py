from abc import ABC, abstractmethod
from typing import Optional
from pydantic import BaseModel

class CertificateStatus(BaseModel):
    issuer_dn: str
    serial_number: str
    revocation_reason: Optional[str]
    revocation_date: Optional[str]
    revoked: bool

class EjbcaClient(ABC):
    @abstractmethod
    def getRevocationstatus(self, serial_number: str) -> CertificateStatus:
        pass

    @abstractmethod
    def getCertificate(self, serial_number: str) -> :
        """Validate a given certificate."""
        pass