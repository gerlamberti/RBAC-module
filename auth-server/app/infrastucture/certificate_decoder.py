import base64
from typing import Callable
from OpenSSL import crypto
from datetime import datetime, timezone

from app.domain.entities.certificate import Certificate, SerialNumber
from app.domain.entities.x509_public_key import X509PublicKey


class CertificateDecoder:
    def __init__(self):
        pass

    def from_raw(self, raw_certificate: str) -> Certificate:
        """
        Maps a raw certificate string to a Certificate entity.

        Args:
            raw_certificate (str): Base64 encoded certificate string.

        Returns:
            Certificate: A domain Certificate entity.
        """
        # Decode Base64
        decoded_cert = base64.b64decode(raw_certificate)
        certificate_header_label = b"-----BEGIN CERTIFICATE-----\n"
        certificate_footer_label = b"\n-----END CERTIFICATE-----"
        full_cert = certificate_header_label + decoded_cert + certificate_footer_label

        # Parse the certificate using OpenSSL
        try:
            x509 = crypto.load_certificate(crypto.FILETYPE_PEM, full_cert)
        except crypto.Error as e:
            raise ValueError("Invalid certificate format") from e

        # Extract fields
        serial_number = x509.get_serial_number()
        
        public_key = crypto.dump_publickey(
            crypto.FILETYPE_PEM, x509.get_pubkey()
        ).decode("utf-8")
        
        expiry_date = datetime.strptime(
            x509.get_notAfter().decode("utf-8"), "%Y%m%d%H%M%SZ"
        ).astimezone(timezone.utc)

        
        subject_components = x509.get_subject()
        subject_components_dict = {key.decode(): value.decode() for key, value in subject_components}

        # Create and return the Certificate entity
        return Certificate(
            serial_id=SerialNumber(serial_number),
            public_key=X509PublicKey(public_key),
            expiry_date=expiry_date,
            subject_components = subject_components_dict
        )
# for testing pourposes
if __name__ == "__main__":
    cert = CertificateDecoder().from_raw("TUlJRVREQ0NBclNnQXdJQkFnSVVIcmwvNi9EZ0c3ZnhpUnk5ZzNDSHJ6QmtkQXN3RFFZSktvWklodmNOQVFFTApCUUF3YlRFeU1EQUdDZ21TSm9tVDhpeGtBUUVNSW1NdFEwVktTR1pQVlhCU1VGTXpUWE16WjFkNVRVcHhRMkY0Ck0yRnZXRzFEZDNVeEZUQVRCZ05WQkFNTURFMWhibUZuWlcxbGJuUkRRVEVUTUJFR0ExVUVDZ3dLUlhoaGJYQnMKWlNCRFFURUxNQWtHQTFVRUJoTUNVMFV3SGhjTk1qTXdOREV3TURNME5EUXhXaGNOTWpVd05EQTVNRE0wTkRRdwpXakJTTVEwd0N3WURWUVFOREFReE1qTTBNUlV3RXdZRFZRUklEQXhVY21GMWJXRjBiMnh2WjI4eEVUQVBCZ29KCmtpYUprL0lzWkFFQkRBRXhNUmN3RlFZRFZRUUREQTVOYVdkMVpXd2dVMjlzYVc1aGN6Q0NBU0l3RFFZSktvWkkKaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFNekF0bDZ0SmQ5aFBYN053TWNraVk1YjZMTVFRN0VxU0ZlLwpWbUJkbDZCQ1oyeG9pZXFhQ1F6T2kxcnFRSTQ2aUxta1Q2dU5TMUhpN3ZhTTIvVFhNSnA2UjBPZ1ErV05CYURQCnJ0UEszNU9zUUtmNnRjQWluKzkyRGRkL211SkFMeWNmeit2ZnBDOC9nMmYySW5XY014MllzSWVZb3FzUmxlMUcKSlJTSm5PVi9hRCtkK1gzUWY1SDR2eUU4VDZzQis3T1RLQ0Y2TXZua2Y1RmlISUl1SmY0cnV2Y0NHTFRONVpSVQpGdnJ2Um5mNUdOU244MUFWMGRCVVNDK2tIMlRjRUxNdkswR0N3WnN2VTM2cThPY3NGL2prN2NFUmRJQnMrM1JjCisrNmpjK0Zaem1LQWJRVjY2OUNqd2NtakFvWFZHeW1oa1NNVDEweFErYThEck55RnJhRUNBd0VBQWFOL01IMHcKREFZRFZSMFRBUUgvQkFJd0FEQWZCZ05WSFNNRUdEQVdnQlJvZUNWRUg4UGptTU5LM3h0WEMwLzJPK2lJK0RBZApCZ05WSFNVRUZqQVVCZ2dyQmdFRkJRY0RBZ1lJS3dZQkJRVUhBd1F3SFFZRFZSME9CQllFRk1GTlVycjR4OW5SCkEweC9rYzk4ZHNqd1FEQ1JNQTRHQTFVZER3RUIvd1FFQXdJRjREQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FZRUEKYlV5UnJOZHE1TkM2OVBNV0R5ZERac29IbGlPUDFZa0hubW13VUEzL1p6aENnSEVDSXVWeE05blQ4RWI1VWNncAo3aUVjU0ZXQmFZY2tOSmZiLzdCSG8zT2dhMGpYRTBsMTZxVTIzazQ1dGVRVGVOdGpsaHhDUldqajgrbmVtMGJ3CjEyc1ZONDRaZExkc0NkOVF0aHFqbHg5cG5JQ2xlMGs4cTh3UU1YVXlYMWFSZEU3SFRqOG9Fc1YrcjdtaTZCaEQKdzUxcFJLRkl6VEhiUEJWOW9VTDg5MVN5NVUvVXJMQWp5Ym05dTg4Y1E1Mk12MXVLRy9Ca2x5dHA5djdydWljagpwMFIzUHZLL3dpeTVzdmdMNmZQdjlUSENVUVMyU280blV4NUxzOVo0c2dYcjNwN0FIVitybyswMWlTWmI0VmRjCkdMc2lYRWtUV2tkWExMdzZESTk5eHFjSVg5QWFNckNURmlnT21MWVFlUHZWTnNHUW84dzIrTUtZbDYzMjdsQm8KcEZNbTNXRUxKdElKU2pBenRnaEtnYmpHdXRpNVNxQThLK09NRmNwUkNJWDBDb1dZRUcrZGZ6U3Q1QXlpVlF1ZQo0cjd1R3Z6cmY4WlRGbGJYMmRrbUkvVFNhN0I2WXJHQ2l3YkMxU2lvVGJjOEp4TldxVmgzcXpscXhnRDkydlhZ")
    print(cert)