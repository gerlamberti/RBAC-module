from abc import ABC, abstractmethod
from typing import Tuple

from app.domain.entities.certificate import Certificate

class CertificateRepository(ABC):
    @abstractmethod
    def is_revoked(self, serial_id: str) -> Tuple[bool, dict]:
        pass

    @abstractmethod
    def get_certificate(self, serial_id: str) -> Tuple[Certificate, dict]:
        pass
