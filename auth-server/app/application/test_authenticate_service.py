from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from app.application.authenticate_service import AuthResponse, AuthenticateService
from app.domain.entities.authorized_keys import AuthorizedKeysBuilder
from app.domain.entities.certificate import Certificate, SerialNumber
from app.domain.entities.x509_public_key import X509PublicKey
from app.domain.repositories.certificate_repository import \
    CertificateRepository


class TestAuthenticateService:
    @pytest.fixture(autouse=True)
    def set_up(self):
        """
        Set up the test environment with a mocked CertificateRepository
        and an instance of AuthenticateService (SUT).
        """
        self.certificate_repository: CertificateRepository = MagicMock()
        self.authorized_keys_builder: AuthorizedKeysBuilder = MagicMock()
        self.service = AuthenticateService(self.certificate_repository,
                                           self.authorized_keys_builder)

    @pytest.fixture()
    def valid_public_key(self):
        pk_mock: X509PublicKey = MagicMock(spec=X509PublicKey)
        pk_mock.pem_key = "test-public"
        return pk_mock

    @pytest.fixture()
    def valid_certificate(self, valid_public_key):
        return Certificate(
            serial_id=SerialNumber(123),
            public_key=valid_public_key,
            expiry_date=datetime.now(timezone.utc) + timedelta(minutes=10),
            subject_components={"emailAddress": "test-email",
                                "CN": "test-CN",
                                "role": "test-role"}
        )

    @pytest.fixture
    def expired_certificate(self, valid_public_key):
        return Certificate(
            serial_id=SerialNumber(123),
            public_key=valid_public_key,
            expiry_date=datetime.now(timezone.utc) - timedelta(minutes=10),
            subject_components={"emailAddress": "test-email",
                                "CN": "test-CN",
                                "role": "test-role"}
        )

    def test_authenticate_success(self, valid_certificate, valid_public_key):
        """
        Test that the service allows authentication for valid and non-expired certificates.
        """
        # Arrange
        self.certificate_repository.is_revoked.return_value = (False, None)
        self.certificate_repository.get_certificate.return_value = (
            valid_certificate, None)
        # mock the authorized_keys_builder.build method
        self.authorized_keys_builder.build.return_value = "test-authorized-keys-entry"

        # Act
        response, err = self.service.authenticate("123ABC", "test-role")

        # Assert
        assert err is None
        assert response.allowed is True
        assert response.authorized_keys_entry == "test-authorized-keys-entry"
        self.certificate_repository.is_revoked.assert_called_once_with(
            "123ABC")
        self.certificate_repository.get_certificate.assert_called_once_with(
            "123ABC")

    def test_authenticate_revoked_certificate(self):
        """
        Test that the service denies authentication for revoked certificates.
        """
        # Arrange
        self.certificate_repository.is_revoked.return_value = (True, None)

        # Act
        response, err = self.service.authenticate("123ABC", "test-role")

        # Assert
        assert response.allowed is False
        assert response.authorized_keys_entry is None
        self.certificate_repository.is_revoked.assert_called_once_with(
            "123ABC")
        self.certificate_repository.get_certificate.assert_not_called()

    def test_authenticate_expired_certificate(self, expired_certificate):
        """
        Test that the service denies authentication for expired certificates.
        """
        # Arrange
        self.certificate_repository.is_revoked.return_value = (False, None)
        self.certificate_repository.get_certificate.return_value = (
            expired_certificate,
            None,
        )

        # Act
        response, err = self.service.authenticate("123ABC", "test-role")

        # Assert
        assert response.allowed is False
        assert response.authorized_keys_entry is None
        self.certificate_repository.is_revoked.assert_called_once_with(
            "123ABC")
        self.certificate_repository.get_certificate.assert_called_once_with(
            "123ABC")

    def test_authenticate_repository_error_on_revoked_check(self):
        """
        Test that the service handles repository errors during the revoked check.
        """
        # Arrange
        self.certificate_repository.is_revoked.return_value = (
            False, "Database error")

        # Act
        response, err = self.service.authenticate("123ABC", "test-role")

        # Assert
        assert response is None
        assert err is not None
        self.certificate_repository.is_revoked.assert_called_once_with(
            "123ABC")
        self.certificate_repository.get_certificate.assert_not_called()

    def test_authenticate_repository_error_on_certificate_fetch(self):
        """
        Test that the service handles repository errors during certificate fetching.
        """
        # Arrange
        self.certificate_repository.is_revoked.return_value = (False, None)
        self.certificate_repository.get_certificate.return_value = (
            None,
            "Database error",
        )

        # Act
        response, err = self.service.authenticate("123ABC", "test-role")

        # Assert
        assert response is None
        assert err is not None
        self.certificate_repository.is_revoked.assert_called_once_with(
            "123ABC")
        self.certificate_repository.get_certificate.assert_called_once_with(
            "123ABC")
