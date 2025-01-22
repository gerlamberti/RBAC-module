from datetime import datetime

import pytest

from app.domain.entities.certificate import Certificate
from app.infrastucture.certificate_decoder import CertificateDecoder


def test_map_raw_to_entity_with_expected_certificate():
    # Arrange
    raw_certificate = "TUlJRVpUQ0NBczJnQXdJQkFnSVVibDF3TTNXbHJZNGhNcXNOVmpvY05MdlV4VFF3RFFZSktvWklodmNOQVFFTApCUUF3YlRFeU1EQUdDZ21TSm9tVDhpeGtBUUVNSW1NdFEwVktTR1pQVlhCU1VGTXpUWE16WjFkNVRVcHhRMkY0Ck0yRnZXRzFEZDNVeEZUQVRCZ05WQkFNTURFMWhibUZuWlcxbGJuUkRRVEVUTUJFR0ExVUVDZ3dLUlhoaGJYQnMKWlNCRFFURUxNQWtHQTFVRUJoTUNVMFV3SGhjTk1qSXhNVEE0TURJME5qVXpXaGNOTWpReE1UQTNNREkwTmpVeQpXakJyTVRJd01BWUtDWkltaVpQeUxHUUJBUXdpWXkxRFJVcElaazlWY0ZKUVV6Tk5jek5uVjNsTlNuRkRZWGd6CllXOVliVU4zZFRFVE1CRUdBMVVFQXd3S1UzVndaWEpCWkcxcGJqRVRNQkVHQTFVRUNnd0tSWGhoYlhCc1pTQkQKUVRFTE1Ba0dBMVVFQmhNQ1UwVXdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFESQppdUhYRlJpclBJeXhEVWVOc1VjSnNqejdSdysvamZUdEJwOHZkcW5HckhtMUhIbzNIWks1My80eU4wZnVYYU9WCmdFNEJia1B2R0JiUGFEcVpuT0g5Vis1YjJxSzFjREJqSVB0YkJLeWppUHRLOUJWemJKNjZRT1dDSlhlQmxKUkkKcnBEYlpocFlyblhDbUVoUU5CZHVoSGR4WHRESjk5cDIrSTNISkY0cUk5RVl2cmRUaVh1R2hDT3ptWm1TcCtxYQppVE4vemRscDJrNW9YdzFoSmc4N1lRalF1NUlOSDY3V2lVQWFMbmhXMGVQOW1HaDBLMXpMZnltWmpBOHplbTgvCi9RdHE5U2FLQjhqQURZMGdPKzNJd0RodGpnZld0R2ZaZVIyM0tUUGlzNEN0a2o0eC9ZamRYcCtJR0cxSUJISGgKcysweHhYZE52NW5xcUFuR1hDdzFBZ01CQUFHamZ6QjlNQXdHQTFVZEV3RUIvd1FDTUFBd0h3WURWUjBqQkJndwpGb0FVYUhnbFJCL0Q0NWpEU3Q4YlZ3dFA5anZvaVBnd0hRWURWUjBsQkJZd0ZBWUlLd1lCQlFVSEF3SUdDQ3NHCkFRVUZCd01FTUIwR0ExVWREZ1FXQkJSUGFkMG9uQ3lycERsN3JnZDJwK1VoZjVBSE1EQU9CZ05WSFE4QkFmOEUKQkFNQ0JlQXdEUVlKS29aSWh2Y05BUUVMQlFBRGdnR0JBRWp3ait5UjcxcmpxK24yeVRLSE9wRFBRU0lJS3p3dQpSQTNLTXdidDQzdFBldVRWWTRsM3RlVStOVTE2d3JaTUMwSGZLQjdHVUtheis2Mm5Jc3NMaXF3Q1p1RGlrQXdQCktiVGx4MlVSYXF3Q1o0SG1tMTJSRDJ2THRZWENrb2RrNjJ6N0RYaVFKQjNCL0xQZzlUSkxpbngra0dkR28wR20KRmhSRTZUN2Y3NjVnUFloQVF5MHcyc1Y0Qi9vc0VjSXBZK3hSaDFSbU4vWWVlYk9tazBoRTVqc0tlK3RySWJzbwpEUE9aWTZ3eC9wbmVIK1pWQ3cvQjJSbHNsaFpzM0VHbXpGYzNMRlN4bFUrSGNWbWdvUTFRRnpqdHZhWWRlVHlOClRDZVlrM3MvZW0ydFhPblRFQUNhQXd4VUZXN3dZYWJKSVk0YmxNbDFMbGtlYzU1czJuYkkzVXY4bklNTzlaZWkKcENwMWZWUnNsUHNyYlNGWkRsUnNGZS8raVE0SHhXZFg4aFBtTnQwc05oY0VtMjdieFJDMytsSEZxZFVhTDRONgp1YU01VHlMSC81VmZGY0E0VkpaT1d1MndWb3RGQnhOMWFSVGdvdEw2MnZhN1IrRmp4elV6KzZ4RENBWUtud1FDClFJQXZsZnVtbUlzN2xSR0dRaS81R1FTcnozWHYrR1Erd2c9PQ=="
    expected_serial_id = "6E5D703375A5AD8E2132AB0D563A1C34BBD4C534"
    expected_public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyIrh1xUYqzyMsQ1HjbFH
CbI8+0cPv4307QafL3apxqx5tRx6Nx2Sud/+MjdH7l2jlYBOAW5D7xgWz2g6mZzh
/VfuW9qitXAwYyD7WwSso4j7SvQVc2yeukDlgiV3gZSUSK6Q22YaWK51wphIUDQX
boR3cV7QyffadviNxyReKiPRGL63U4l7hoQjs5mZkqfqmokzf83ZadpOaF8NYSYP
O2EI0LuSDR+u1olAGi54VtHj/ZhodCtcy38pmYwPM3pvP/0LavUmigfIwA2NIDvt
yMA4bY4H1rRn2Xkdtykz4rOArZI+Mf2I3V6fiBhtSARx4bPtMcV3Tb+Z6qgJxlws
NQIDAQAB
-----END PUBLIC KEY-----
"""
    expected_expiry_date = datetime(year=2024,
                                    month=11,
                                    day=7,
                                    hour=2,
                                    minute=46,
                                    second=52)

    # Act
    certificate = CertificateDecoder().from_raw(raw_certificate)

    # Assert
    assert isinstance(
        certificate, Certificate), "Result should be a Certificate entity"
    assert certificate.serial_id.to_hex_uppercase(
    ) == expected_serial_id, "Serial ID mismatch"
    assert certificate.public_key == expected_public_key, "Public key mismatch"
    assert certificate.expiry_date == expected_expiry_date, "Expiry date mismatch"


def test_map_raw_to_entity_with_invalid_format_certificate():
    # Arrange
    raw_certificate = "some invalid certificate"

    # Act
    with pytest.raises(Exception) as certificate_exception:
        certificate = CertificateDecoder().from_raw(raw_certificate)

    # Assert
    assert certificate_exception is not None, "Exception should be raised"
