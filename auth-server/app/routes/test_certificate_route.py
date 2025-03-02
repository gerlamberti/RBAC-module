import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi import HTTPException, status
from app.application.authenticate_service import AuthResponse
from app.routes.certificate_route import validate


@pytest.fixture
def mock_authenticate_service():
    """Mock the AuthenticateService dependency."""
    service_mock = MagicMock()
    service_mock.authenticate = MagicMock()
    return service_mock


def test_validate_certificate_valid(mock_authenticate_service):
    """Should return AuthResponse(allowed=True) when authentication is successful."""
    mock_authenticate_service.authenticate.return_value = (
        AuthResponse(allowed=True, authorized_keys_entry="mocked-ssh-key"),
        None
    )

    response = validate("123ABC", "admin", mock_authenticate_service)

    assert response.allowed is True
    assert response.authorized_keys_entry == "mocked-ssh-key"
    mock_authenticate_service.authenticate.assert_called_once_with("123ABC", "admin")


def test_validate_certificate_not_found(mock_authenticate_service):
    """Should raise 400 Bad Request if the certificate is not found."""
    mock_authenticate_service.authenticate.return_value = (
        None,
        {"error": "Certificate not found"}
    )

    with pytest.raises(HTTPException) as exc_info:
        validate("123ABC", "admin", mock_authenticate_service)

    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == {"error": "Certificate not found"}
    mock_authenticate_service.authenticate.assert_called_once_with("123ABC", "admin")


def test_validate_certificate_revoked(mock_authenticate_service):
    """Should raise 403 Forbidden if the certificate is revoked."""
    mock_authenticate_service.authenticate.return_value = (
        AuthResponse(allowed=False),
        None
    )

    with pytest.raises(HTTPException) as exc_info:
        validate("123ABC", "admin", mock_authenticate_service)

    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert exc_info.value.detail == "El certificado está revocado."
    mock_authenticate_service.authenticate.assert_called_once_with("123ABC", "admin")


def test_validate_revocation_check_fails(mock_authenticate_service):
    """Should raise 400 Bad Request if revocation check fails."""
    mock_authenticate_service.authenticate.return_value = (
        None,
        {"error": "Revocation check failed"}
    )

    with pytest.raises(HTTPException) as exc_info:
        validate("123ABC", "admin", mock_authenticate_service)

    assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
    assert exc_info.value.detail == {"error": "Revocation check failed"}
    mock_authenticate_service.authenticate.assert_called_once_with("123ABC", "admin")


def test_validate_internal_server_error(mock_authenticate_service):
    """Should raise 500 Internal Server Error if an unexpected exception occurs."""
    mock_authenticate_service.authenticate.side_effect = Exception("Unexpected error")

    with pytest.raises(HTTPException) as exc_info:
        validate("123ABC", "admin", mock_authenticate_service)

    assert exc_info.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert exc_info.value.detail == "Error interno. Contactar al administrador."
    mock_authenticate_service.authenticate.assert_called_once_with("123ABC", "admin")
