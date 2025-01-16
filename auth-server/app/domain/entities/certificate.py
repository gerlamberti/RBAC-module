from datetime import datetime, timezone
from typing import Union

class Certificate:
    def __init__(self, serial_id: str, public_key: str, expiry_date: datetime):
        if not isinstance(expiry_date, datetime):
            raise ValueError("expiry_date must be a datetime object")
        
        self.serial_id = serial_id
        self.public_key = public_key
        self.expiry_date = expiry_date

    def is_expired(self, now: datetime = datetime.now(timezone.utc)) -> bool:
        return now > self.expiry_date

    def __repr__(self) -> str:
        return (f"Certificate(serial_id='{self.serial_id}', "
                f"public_key='{self.public_key}', "
                f"expiry_date='{self.expiry_date.isoformat()}')")