import unittest
from unittest.mock import MagicMock
from datetime import datetime, timedelta

import pytest

from app.application.authenticate_service import AuthenticateService
from app.domain.entities.certificate import Certificate


class TestAuthenticateService(unittest.TestCase):
    def setUp(self):
        """
        Set up the test environment with a mocked CertificateRepository
        and an instance of AuthenticateService (SUT).
        """
        self.certificate_repository = MagicMock()
        self.service = AuthenticateService(self.certificate_repository)

    @pytest.fixture
    def valid_certificate(self):
        return Certificate(
            serial_id="123ABC",
            public_key="test-public-key",
            expiry_date=datetime.now() + timedelta(minutes=10),
        )

    @pytest.fixture
    def expired_certificate(self):
        return Certificate(
            serial_id="123ABC",
            public_key="test-public-key",
            expiry_date=datetime.now() - timedelta(minutes=10),
        )

    def test_authenticate_success(self, valid_certificate):
        """
        Test that the service allows authentication for valid and non-expired certificates.
        """
        # Arrange
        self.certificate_repository.is_revoked.return_value = (False, None)
        self.certificate_repository.get_certificate.return_value = valid_certificate

        # Act
        response, err = self.service.authenticate("123ABC")

        # Assert
        self.assertIsNone(err)
        self.assertTrue(response.allowed)
        self.assertEqual(response.public_key, "test-public-key")
        self.certificate_repository.is_revoked.assert_called_once_with("123ABC")
        self.certificate_repository.get_certificate.assert_called_once_with("123ABC")

    def test_authenticate_revoked_certificate(self):
        """
        Test that the service denies authentication for revoked certificates.
        """
        # Arrange
        self.certificate_repository.is_revoked.return_value = (True, None)

        # Act
        response, err = self.service.authenticate("123ABC")

        # Assert
        self.assertFalse(response.allowed)
        self.assertIsNone(response.public_key)
        self.certificate_repository.is_revoked.assert_called_once_with("123ABC")
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
        response, err = self.service.authenticate("123ABC")

        # Assert
        self.assertFalse(response.allowed)
        self.assertIsNone(response.public_key)
        self.certificate_repository.is_revoked.assert_called_once_with("123ABC")
        self.certificate_repository.get_certificate.assert_called_once_with("123ABC")

    def test_authenticate_repository_error_on_revoked_check(self):
        """
        Test that the service handles repository errors during the revoked check.
        """
        # Arrange
        self.certificate_repository.is_revoked.return_value = (False, "Database error")

        # Act
        response, err = self.service.authenticate("123ABC")

        # Assert
        self.assertIsNone(response)
        self.assertIsNotNone(err)
        self.certificate_repository.is_revoked.assert_called_once_with("123ABC")
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
        response, err = self.service.authenticate("123ABC")

        # Assert
        self.assertIsNone(response)
        self.assertIsNotNone(err)
        self.certificate_repository.is_revoked.assert_called_once_with("123ABC")
        self.certificate_repository.get_certificate.assert_called_once_with("123ABC")


if __name__ == "__main__":
    unittest.main()
