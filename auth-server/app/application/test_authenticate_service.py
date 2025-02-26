from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from app.application.authenticate_service import AuthenticateService
from app.domain.entities.authorized_keys import AuthorizedKeysBuilder
from app.domain.entities.certificate import Certificate, SerialNumber
from app.domain.entities.x509_public_key import X509PublicKey
from app.domain.repositories.certificate_repository import CertificateRepository

# pylint: disable=attribute-defined-outside-init,missing-class-docstring,missing-function-docstring


class TestAuthenticateService:
    CERT_ID = "123ABC"
    ROLE = "test-role"
    AUTHORIZED_ENTRY = "test-authorized-keys-entry"

    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up the test environment."""
        self.certificate_repository: CertificateRepository = MagicMock()
        self.authorized_keys_builder: AuthorizedKeysBuilder = MagicMock()
        self.service = AuthenticateService(
            self.certificate_repository, self.authorized_keys_builder)

    @pytest.fixture
    def valid_public_key_fixture(self):
        key = MagicMock(spec=X509PublicKey)
        key.pem_key = "test-public"
        return key

    @pytest.fixture
    def valid_certificate_fixture(self, valid_public_key_fixture):
        return Certificate(
            serial_id=SerialNumber(123),
            public_key=valid_public_key_fixture,
            expiry_date=datetime.now(timezone.utc) + timedelta(minutes=10),
            subject_components={"emailAddress": "test-email",
                                "CN": "test-CN", "role": self.ROLE}
        )

    @pytest.fixture
    def expired_certificate_fixture(self, valid_public_key_fixture):
        return Certificate(
            serial_id=SerialNumber(123),
            public_key=valid_public_key_fixture,
            expiry_date=datetime.now(timezone.utc) - timedelta(minutes=10),
            subject_components={"emailAddress": "test-email",
                                "CN": "test-CN", "role": self.ROLE}
        )

    def test_authenticate_success(self, valid_certificate_fixture):
        """Ensures authentication succeeds for a valid, non-expired certificate."""
        self.certificate_repository.is_revoked.return_value = (False, None)
        self.certificate_repository.get_certificate.return_value = (
            valid_certificate_fixture, None)
        self.authorized_keys_builder.build.return_value = self.AUTHORIZED_ENTRY

        response, err = self.service.authenticate(self.CERT_ID, self.ROLE)

        assert err is None
        assert response.allowed is True
        assert response.authorized_keys_entry == self.AUTHORIZED_ENTRY
        self.certificate_repository.is_revoked.assert_called_once_with(
            self.CERT_ID)
        self.certificate_repository.get_certificate.assert_called_once_with(
            self.CERT_ID)

    def test_authenticate_revoked_certificate(self):
        """Ensures authentication fails when the certificate is revoked."""
        self.certificate_repository.is_revoked.return_value = (True, None)

        response, err = self.service.authenticate(self.CERT_ID, self.ROLE)

        assert response.allowed is False
        assert response.authorized_keys_entry is None
        self.certificate_repository.is_revoked.assert_called_once_with(
            self.CERT_ID)
        self.certificate_repository.get_certificate.assert_not_called()

    def test_authenticate_expired_certificate(self, expired_certificate_fixture):
        """Ensures authentication fails for an expired certificate."""
        self.certificate_repository.is_revoked.return_value = (False, None)
        self.certificate_repository.get_certificate.return_value = (
            expired_certificate_fixture, None)

        response, err = self.service.authenticate(self.CERT_ID, self.ROLE)

        assert response.allowed is False
        assert response.authorized_keys_entry is None
        self.certificate_repository.is_revoked.assert_called_once_with(
            self.CERT_ID)
        self.certificate_repository.get_certificate.assert_called_once_with(
            self.CERT_ID)

    def test_authenticate_repository_error_on_revoked_check(self):
        """Ensures authentication fails gracefully when the revoked check fails."""
        self.certificate_repository.is_revoked.return_value = (
            False, "Database error")

        response, err = self.service.authenticate(self.CERT_ID, self.ROLE)

        assert response is None
        assert err is not None
        self.certificate_repository.is_revoked.assert_called_once_with(
            self.CERT_ID)
        self.certificate_repository.get_certificate.assert_not_called()

    def test_authenticate_repository_error_on_certificate_fetch(self):
        """Ensures authentication fails gracefully when fetching the certificate fails."""
        self.certificate_repository.is_revoked.return_value = (False, None)
        self.certificate_repository.get_certificate.return_value = (
            None, "Database error")

        response, err = self.service.authenticate(self.CERT_ID, self.ROLE)

        assert response is None
        assert err is not None
        self.certificate_repository.is_revoked.assert_called_once_with(
            self.CERT_ID)
        self.certificate_repository.get_certificate.assert_called_once_with(
            self.CERT_ID)

    def test_authorized_keys_builder_is_called(self, valid_certificate_fixture):
        """Ensures the authorized keys builder is invoked with correct arguments."""
        self.certificate_repository.is_revoked.return_value = (False, None)
        self.certificate_repository.get_certificate.return_value = (
            valid_certificate_fixture, None)
        self.authorized_keys_builder.build.return_value = self.AUTHORIZED_ENTRY

        self.service.authenticate(self.CERT_ID, self.ROLE)

        self.authorized_keys_builder.build.assert_called_once_with(
            valid_certificate_fixture.subject_components["emailAddress"],
            valid_certificate_fixture.subject_components["CN"],
            valid_certificate_fixture.subject_components["role"],
            valid_certificate_fixture.public_key
        )
