from datetime import datetime, timezone
from enum import Enum

from app.domain.entities.x509_public_key import X509PublicKey

class SerialNumber():
    def __init__(self, serial_number: int):
        self.serial_number = serial_number
    def to_hex_uppercase(self) -> str:
        return format(self.serial_number, 'X')

class Certificate:
    def __init__(self, 
                 serial_id: SerialNumber, 
                 public_key: X509PublicKey, 
                 expiry_date: datetime,
                 subject_components: list[tuple[bytes, bytes]]
                 ):
        if not isinstance(public_key, X509PublicKey):
            raise ValueError("public_key must be an X509PublicKey object")
        if not isinstance(expiry_date, datetime):
            raise ValueError("expiry_date must be a datetime object")
        if not isinstance(serial_id, SerialNumber):
            raise ValueError("serial_id must be a SerialNumber object")
        # Ensure expiry_date is timezone-aware, otherwise raise an error
        if expiry_date.tzinfo is None:
            raise ValueError("expiry_date must be a timezone-aware datetime")
        
        self.serial_id = serial_id
        self.public_key = public_key
        self.expiry_date = expiry_date
        self.subject_components = subject_components

    def is_expired(self, now: datetime = datetime.now(timezone.utc)) -> bool:
        return now > self.expiry_date

    def __repr__(self) -> str:
        return (f"Certificate(serial_id='{self.serial_id}', "
                f"public_key='{self.public_key}', "
                f"expiry_date='{self.expiry_date.isoformat()}')")
    

class CertError(Enum):
    CERTIFICATE_NOT_FOUND = "certificate not found"