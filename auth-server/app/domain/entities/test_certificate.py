from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
import pytest
from app.domain.entities.certificate import Certificate, SerialNumber
from app.domain.entities.x509_public_key import X509PublicKey


@pytest.fixture
def valid_expiry_date():
    """Retorna una fecha de expiración válida en el futuro."""
    return datetime.now(timezone.utc) + timedelta(days=1)


@pytest.fixture
def mock_public_key():
    """Retorna un mock de una clave pública X509."""
    return MagicMock(spec=X509PublicKey)


def test_certificate_creation_fails_with_invalid_public_key(valid_expiry_date):
    """Verifica que se lance un error cuando se proporciona una clave pública inválida."""
    invalid_pk = "123"
    with pytest.raises(ValueError) as e:
        Certificate(
            serial_id=SerialNumber(123456),
            public_key=invalid_pk,
            expiry_date=valid_expiry_date,
            subject_components={"emailAddress": "test-email",
                                "CN": "test-CN", "role": "test-role"}
        )
    assert str(e.value) == "public_key must be an X509PublicKey object", "Debe lanzarse un error si la clave pública no es válida"


def test_certificate_creation_fails_with_invalid_serial_id(valid_expiry_date, mock_public_key):
    """Verifica que se lance un error cuando el ID de serie es inválido."""
    with pytest.raises(ValueError) as e:
        Certificate(
            serial_id="invalid_serial_id",
            public_key=mock_public_key,
            expiry_date=valid_expiry_date,
            subject_components={}
        )
    assert str(
        e.value) == "serial_id must be a SerialNumber object", "Debe lanzarse un error si el ID de serie no es válido"


def test_certificate_creation_fails_with_naive_expiry_date(mock_public_key):
    """Verifica que se lance un error cuando la fecha de expiración no tiene zona horaria."""
    with pytest.raises(ValueError) as e:
        Certificate(
            serial_id=SerialNumber(123456),
            public_key=mock_public_key,
            expiry_date=datetime.now(),
            subject_components={}
        )
    assert str(e.value) == "expiry_date must be a timezone-aware datetime", "Debe lanzarse un error si la fecha de expiración no tiene zona horaria"


def test_valid_certificate_is_not_expired(valid_expiry_date, mock_public_key):
    """Verifica que un certificado válido no esté expirado."""
    certificate = Certificate(
        serial_id=SerialNumber(123456),
        public_key=mock_public_key,
        expiry_date=valid_expiry_date,
        subject_components={"emailAddress": "test-email",
                            "CN": "test-CN", "role": "test-role"}
    )
    assert certificate.is_expired() is False, "Un certificado válido no debe estar expirado"
