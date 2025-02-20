import re
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.exceptions import InvalidKey

class X509PublicKey:
    """Encapsulates an X.509 public key with validation."""
    PEM_PUBLIC_KEY_PATTERN = re.compile(
        r"-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/=\n]+)\n-----END PUBLIC KEY-----"
    )

    def __init__(self, pem_key: str):
        self._validate_pem_format(pem_key)
        self._validate_crypto_structure(pem_key)
        self.pem_key = pem_key  # Store valid PEM key

    def _validate_pem_format(self, pem_key: str):
        """Ensure the key is in valid PEM format."""
        if not isinstance(pem_key, str) or not pem_key.strip():
            raise ValueError("X.509 public key must be a non-empty string")
        if not self.PEM_PUBLIC_KEY_PATTERN.match(pem_key):
            raise ValueError("Invalid X.509 PEM public key format")

    def _validate_crypto_structure(self, pem_key: str):
        """Ensure the key can be parsed as a valid X.509 public key."""
        try:
            key_obj = serialization.load_pem_public_key(pem_key.encode())
            if not isinstance(key_obj, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
                raise ValueError("Unsupported public key type (must be RSA or EC)")
        except (ValueError, InvalidKey):
            raise ValueError("Invalid X.509 public key: cannot be parsed")

    def __repr__(self) -> str:
        return f"X509PublicKey(pem_key='{self.pem_key[:30]}...')"  # Truncated for readability

