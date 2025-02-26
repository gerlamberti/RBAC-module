import pytest
import requests
import tempfile
import os
from unittest.mock import MagicMock

from app.clients.ejbca_client import EJBCAClient


@pytest.fixture(scope="module")
def temp_cert_files():
    """Creates temporary PEM and key files with hardcoded values."""
    key_content = b"""-----BEGIN PRIVATE KEY-----\nMII...FAKE_KEY...==\n-----END PRIVATE KEY-----\n"""
    cert_content = b"""-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7w==\n-----END CERTIFICATE-----\n"""

    key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    key_file.write(key_content)
    key_file.close()

    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    cert_file.write(cert_content)
    cert_file.close()

    yield key_file.name, cert_file.name

    os.remove(key_file.name)
    os.remove(cert_file.name)


@pytest.fixture
def mock_session():
    """Fixture para crear una sesión simulada de requests."""
    return MagicMock(spec=requests.Session)


@pytest.fixture
def ejbca_client(mock_session, temp_cert_files):
    """Crea una instancia de EJBCAClient con una sesión simulada y certificados temporales."""
    key_path, cert_path = temp_cert_files
    return EJBCAClient(
        base_url="https://ejbca.example.com",
        key_path=key_path,
        cert_password=cert_path,
        session=mock_session
    )


def test_get_revocation_status_success(ejbca_client, mock_session):
    """Prueba que la función devuelva un estado de revocación exitoso."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "issuer_dn": "CN=Test CA",
        "serial_number": "123456",
        "revocation_reason": "Key Compromise",
        "revocation_date": "2025-01-01T12:00:00Z",
        "message": "Revoked",
        "revoked": True
    }
    mock_session.get.return_value = mock_response

    status, err = ejbca_client.get_revocation_status("CN=Test CA", "123456")

    assert err is None
    assert status.revoked is True
    assert status.revocation_reason == "Key Compromise"
    mock_session.get.assert_called_once()


def test_get_revocation_status_not_found(ejbca_client, mock_session):
    """Prueba que se maneje correctamente cuando un certificado no es encontrado."""
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_session.get.return_value = mock_response

    status, err = ejbca_client.get_revocation_status("CN=Test CA", "999999")

    assert status is None
    assert err == {"detail": "Certificate with serial 999999 not found"}
    mock_session.get.assert_called_once()


def test_search_success(ejbca_client, mock_session):
    """Prueba que la búsqueda de certificados devuelva resultados válidos."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"certificates": [
        {"serial_number": "12345", "status": "VALID"}]}
    mock_session.post.return_value = mock_response

    results, err = ejbca_client.search(
        10, [{"property": "QUERY", "value": "test", "operation": "LIKE"}])

    assert err is None
    assert "certificates" in results
    assert results["certificates"][0]["serial_number"] == "12345"
    mock_session.post.assert_called_once()


def test_search_failure(ejbca_client, mock_session):
    """Prueba que la búsqueda maneje correctamente un error de solicitud."""
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    mock_session.post.return_value = mock_response

    results, err = ejbca_client.search(
        10, [{"property": "QUERY", "value": "test", "operation": "LIKE"}])

    assert results is None
    assert err.get("error") == "Internal Server Error"
    assert err.get("url") == "https://ejbca.example.com/v1/certificate/search"
    mock_session.post.assert_called_once()


def test_invalid_key_path():
    """Prueba que se genere un error si el archivo de clave no existe."""
    with pytest.raises(ValueError, match="Key file not found: /invalid/path.pem"):
        EJBCAClient("https://ejbca.example.com",
                    "/invalid/path.pem", "password")


def test_invalid_cert_path():
    """Prueba que se genere un error si el archivo del certificado no existe."""
    with pytest.raises(ValueError, match="Key file not found: /nonexistent/cert.pem"):
        EJBCAClient("https://ejbca.example.com",
                    "/nonexistent/cert.pem", "password")
