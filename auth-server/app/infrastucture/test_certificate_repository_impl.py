import pytest
from unittest.mock import MagicMock
from app.domain.entities.certificate import Certificate
from app.domain.repositories.certificate_repository import CertificateRepository
from app.infrastucture.certificate_decoder import CertificateDecoder
from app.clients.ejbca_client import EJBCAClient
from app.infrastucture.certificate_repository_impl import CertificateRespositoryImpl


@pytest.fixture
def ejbca_client():
    """Mock del cliente de EJBCA."""
    return MagicMock(spec=EJBCAClient)


@pytest.fixture
def certificate_decoder():
    """Mock del decodificador de certificados."""
    return MagicMock(spec=CertificateDecoder)


@pytest.fixture
def repository(ejbca_client, certificate_decoder):
    """Instancia del repositorio con dependencias mockeadas."""
    return CertificateRespositoryImpl(ejbca_client, certificate_decoder)


@pytest.fixture
def mock_certificate():
    """Mock de un certificado válido."""
    cert = MagicMock(spec=Certificate)
    cert.serial_id = "123ABC"
    return cert


# --- PRUEBAS PARA is_revoked ---

def test_is_revoked_returns_true(repository, ejbca_client):
    """Debe retornar True si el certificado está revocado."""
    ejbca_client.get_revocation_status.return_value = (MagicMock(revoked=True), None)

    revoked, err = repository.is_revoked("123ABC")

    assert err is None
    assert revoked is True
    ejbca_client.get_revocation_status.assert_called_once()


def test_is_revoked_returns_false(repository, ejbca_client):
    """Debe retornar False si el certificado no está revocado."""
    ejbca_client.get_revocation_status.return_value = (MagicMock(revoked=False), None)

    revoked, err = repository.is_revoked("123ABC")

    assert err is None
    assert revoked is False
    ejbca_client.get_revocation_status.assert_called_once()


def test_is_revoked_handles_error(repository, ejbca_client):
    """Debe manejar el error si EJBCAClient falla."""
    ejbca_client.get_revocation_status.return_value = (None, {"error": "EJBCA error"})

    revoked, err = repository.is_revoked("123ABC")

    assert revoked is None
    assert err == {"error": "EJBCA error"}
    ejbca_client.get_revocation_status.assert_called_once()


# --- PRUEBAS PARA get_certificate ---

def test_get_certificate_success(repository, ejbca_client, certificate_decoder, mock_certificate):
    """Debe retornar un certificado válido si la búsqueda es exitosa."""
    ejbca_client.search.return_value = (
        {"certificates": [{"serial_number": "123ABC", "certificate": "raw_cert"}]},
        None
    )
    certificate_decoder.from_raw.return_value = mock_certificate

    cert, err = repository.get_certificate("123ABC")

    assert err is None
    assert cert == mock_certificate
    ejbca_client.search.assert_called_once()
    certificate_decoder.from_raw.assert_called_once_with("raw_cert")


def test_get_certificate_not_found(repository, ejbca_client):
    """Debe manejar error si el certificado no es encontrado en la búsqueda."""
    ejbca_client.search.return_value = ({"certificates": []}, None)

    cert, err = repository.get_certificate("123ABC")

    assert cert is None
    assert err is not None
    assert err["error"] == "No se encontraron certificados"
    ejbca_client.search.assert_called_once()


def test_get_certificate_serial_mismatch(repository, ejbca_client):
    """Debe manejar error si el serial devuelto no coincide con el buscado."""
    ejbca_client.search.return_value = (
        {"certificates": [{"serial_number": "DIFFERENT", "certificate": "raw_cert"}]},
        None
    )

    cert, err = repository.get_certificate("123ABC")

    assert cert is None
    assert err == {
        "error": "El serial no coincide con el buscado",
        "original_serial": "123ABC",
        "found_serial": "DIFFERENT"
    }
    ejbca_client.search.assert_called_once()


def test_get_certificate_decode_failure(repository, ejbca_client, certificate_decoder):
    """Debe manejar error si la decodificación del certificado falla."""
    ejbca_client.search.return_value = (
        {"certificates": [{"serial_number": "123ABC", "certificate": "raw_cert"}]},
        None
    )
    certificate_decoder.from_raw.side_effect = ValueError("Decoding error")

    cert, err = repository.get_certificate("123ABC")

    assert cert is None
    assert err.get("error") == "Error al decodificar certificado"
    ejbca_client.search.assert_called_once()
    certificate_decoder.from_raw.assert_called_once_with("raw_cert")
