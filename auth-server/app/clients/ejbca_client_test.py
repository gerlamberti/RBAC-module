import pytest
import os
from unittest.mock import Mock, patch
from requests.exceptions import RequestException
from fastapi import HTTPException
from clients.ejbca_client import EJBCAClient

@pytest.fixture
def valid_cert_files(tmp_path):
    """Create temporary certificate and key files for testing."""
    cert_file = tmp_path / "test.crt"
    key_file = tmp_path / "test.key"
    
    # Create dummy files
    cert_file.write_text("dummy cert content")
    key_file.write_text("dummy key content")
    
    return str(cert_file), str(key_file)

@pytest.fixture
def ejbca_client(valid_cert_files):
    """Create an EJBCAClient instance with valid certificate files."""
    cert_path, key_path = valid_cert_files
    return EJBCAClient(
        base_url="https://ejbca.example.com",
        certificate_path=cert_path,
        key_path=key_path
    )

class TestEJBCAClientInitialization:
    def test_successful_initialization(self, valid_cert_files):
        """Test successful client initialization with valid files."""
        cert_path, key_path = valid_cert_files
        client = EJBCAClient(
            base_url="https://ejbca.example.com",
            certificate_path=cert_path,
            key_path=key_path
        )
        assert client.base_url == "https://ejbca.example.com"
        assert client.certificate_path == (cert_path, key_path)
        assert client.session is not None

    def test_initialization_missing_cert(self, tmp_path):
        """Test initialization fails with missing certificate file."""
        key_file = tmp_path / "test.key"
        key_file.write_text("dummy key content")
        
        with pytest.raises(ValueError, match="Certificate file not found"):
            EJBCAClient(
                base_url="https://ejbca.example.com",
                certificate_path="/nonexistent/cert.crt",
                key_path=str(key_file)
            )

    def test_initialization_missing_key(self, tmp_path):
        """Test initialization fails with missing key file."""
        cert_file = tmp_path / "test.crt"
        cert_file.write_text("dummy cert content")
        
        with pytest.raises(ValueError, match="Key file not found"):
            EJBCAClient(
                base_url="https://ejbca.example.com",
                certificate_path=str(cert_file),
                key_path="/nonexistent/key.key"
            )

class TestEJBCAClientCertificateFetching:
    def test_successful_certificate_fetch(self, ejbca_client):
        """Test successful certificate fetch with valid serial number."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"certificate": "mock_cert_data"}
        
        with patch.object(ejbca_client.session, 'get', return_value=mock_response):
            result = ejbca_client.fetch_certificate("123456")
            assert result == {"certificate": "mock_cert_data"}

    def test_certificate_not_found(self, ejbca_client):
        """Test certificate fetch when certificate doesn't exist."""
        mock_response = Mock()
        mock_response.status_code = 404
        
        with patch.object(ejbca_client.session, 'get', return_value=mock_response):
            result = ejbca_client.fetch_certificate("nonexistent")
            assert result is None

    def test_certificate_fetch_error(self, ejbca_client):
        """Test certificate fetch with server error."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        
        with patch.object(ejbca_client.session, 'get', return_value=mock_response):
            with pytest.raises(HTTPException) as exc_info:
                ejbca_client.fetch_certificate("123456")
            assert exc_info.value.status_code == 500
            assert "Error fetching certificate" in str(exc_info.value.detail)

    def test_connection_error(self, ejbca_client):
        """Test certificate fetch with connection error."""
        with patch.object(ejbca_client.session, 'get', side_effect=RequestException("Connection failed")):
            with pytest.raises(HTTPException) as exc_info:
                ejbca_client.fetch_certificate("123456")
            assert exc_info.value.status_code == 500
            assert "Failed to connect to EJBCA" in str(exc_info.value.detail)

class TestEJBCAClientFileValidation:
    def test_validate_existing_readable_file(self, tmp_path):
        """Test file validation with existing readable file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        
        client = EJBCAClient(
            base_url="https://ejbca.example.com",
            certificate_path=str(test_file),
            key_path=str(test_file)
        )
        assert client._validate_file(str(test_file)) is True

    def test_validate_nonexistent_file(self):
        """Test file validation with nonexistent file."""
        client = EJBCAClient(
            base_url="https://ejbca.example.com",
            certificate_path="/path/to/cert.crt",
            key_path="/path/to/key.key"
        )
        assert client._validate_file("/nonexistent/file.txt") is False

    @pytest.mark.skipif(os.name == "nt", reason="Permission tests not applicable on Windows")
    def test_validate_unreadable_file(self, tmp_path):
        """Test file validation with unreadable file."""
        test_file = tmp_path / "unreadable.txt"
        test_file.write_text("test content")
        os.chmod(str(test_file), 0o000)
        
        client = EJBCAClient(
            base_url="https://ejbca.example.com",
            certificate_path="/path/to/cert.crt",
            key_path="/path/to/key.key"
        )
        try:
            assert client._validate_file(str(test_file)) is False
        finally:
            # Restore permissions so the file can be cleaned up
            os.chmod(str(test_file), 0o600)