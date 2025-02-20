from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from pytest import raises

from app.domain.entities.x509_public_key import X509PublicKey

def generate_rsa_public_key():
    """Generates an RSA public key using OpenSSL via the cryptography module."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048  # Secure default
    )
    
    public_key = private_key.public_key()
    
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_public_key.decode()

def generate_ec_public_key():
    """Generates an EC (Elliptic Curve) public key using OpenSSL via the cryptography module."""
    private_key = ec.generate_private_key(ec.SECP256R1())  # Common curve choice
    
    public_key = private_key.public_key()
    
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_public_key.decode()


def test_invalid_x509_public_key():
    """Test that an invalid X.509 public key raises an exception."""
    # Arrange
    invalid_key = generate_rsa_public_key()[:-10]  # Remove last 10 characters
    # Act
    with raises(ValueError) as e:
        X509PublicKey(pem_key=invalid_key)
    # Assert
    assert e.value is not None, "Invalid X.509 public key should raise an exception"
def test_valid_rsa_public_key():
    """Test that the generated RSA public key is valid."""
    # Arrange
    rsa_pub_key = generate_rsa_public_key()
    # Act
    pk = X509PublicKey(pem_key=rsa_pub_key)
    # Assert
    assert pk.pem_key == rsa_pub_key, "RSA public key should be valid"
def test_valid_ec_public_key():
    """Test that the generated EC public key is valid."""
    # Arrange
    ec_pub_key = generate_ec_public_key()
    # Act
    pk = X509PublicKey(pem_key=ec_pub_key)
    # Assert
    assert pk.pem_key == ec_pub_key, "EC public key should be valid"
