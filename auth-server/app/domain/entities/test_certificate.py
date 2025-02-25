from datetime import datetime, timezone, timedelta
from unittest.mock import Mock

import pytest
from app.domain.entities.certificate import Certificate, SerialNumber
from app.domain.entities.x509_public_key import X509PublicKey


def test_invalid_public_key():
    # Act
    invalid_pk = "123"
    with pytest.raises(ValueError) as e:
         Certificate(
            serial_id=SerialNumber(123456),
            public_key=invalid_pk,
            expiry_date=valid_expiry_date(),
            subject_components={"emailAddress": "test-email",
                                "CN": "test-CN",
                                "role": "test-role"}
        )
    # Assert
    assert str(
        e.value) == "public_key must be an X509PublicKey object", "Invalid public_key should raise an exception"


def test_invalid_serial_id():
    # Act
    with pytest.raises(ValueError) as e:
        certificate = Certificate(
            serial_id="invalid_serial_id",
            public_key=Mock(spec=X509PublicKey),
            expiry_date=valid_expiry_date(),
            subject_components={}
        )
    # Assert
    assert str(
        e.value) == "serial_id must be a SerialNumber object", "Invalid serial_id should raise an exception"


def test_naive_expiry_date():
    # Act
    with pytest.raises(ValueError) as e:
        certificate = Certificate(
            serial_id=SerialNumber(123456),
            public_key=Mock(spec=X509PublicKey),
            expiry_date=datetime.now(),
            subject_components={}
        )
    # Assert
    assert str(
        e.value) == "expiry_date must be a timezone-aware datetime", "Naive expiry_date should raise an exception"


def test_valid_certificate():
    # Act
    certificate = Certificate(
        serial_id=SerialNumber(123456),
        public_key=Mock(spec=X509PublicKey),
        expiry_date=valid_expiry_date(),
        subject_components={ "emailAddress": "test-email",
                             "CN": "test-CN",
                             "role": "test-role"}
    )
    # Assert
    assert certificate.is_expired() == False, "Certificate should not be expired"

# Helper function to return a valid expiry date

def valid_expiry_date():
    return datetime.now(timezone.utc) + timedelta(days=1)
