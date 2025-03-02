from typing import Tuple

from app.clients.ejbca_client import EJBCAClient
from app.domain.entities.certificate import Certificate
from app.domain.repositories.certificate_repository import \
    CertificateRepository
from app.infrastucture.certificate_decoder import CertificateDecoder


class CertificateRespositoryImpl(CertificateRepository):
    def __init__(
        self,
        ejbca_client: EJBCAClient,
        certificate_decoder: CertificateDecoder,
        issuer_dn: str,
    ):
        self.ejbca_client = ejbca_client
        self.certificate_decoder = certificate_decoder
        self.issuer_dn = issuer_dn

    def is_revoked(self, serial_id) -> Tuple[bool, dict]:
        revocationStatus, err = self.ejbca_client.get_revocation_status(
            self.issuer_dn, serial_id
        )
        if err:
            return None, err
        return revocationStatus.revoked, None

    def get_certificate(self, serial_id) -> Tuple[Certificate, dict]:
        search_criteria = [
            {"property": "QUERY", "value": serial_id, "operation": "EQUAL"}
        ]

        search_response, err = self.ejbca_client.search(
            max_results=1, criteria=search_criteria
        )

        if err is not None:
            return None, {
                "error": f"Fallo busqueda de certificado con serial: {serial_id}",
                "cause": err,
            }

        try:
            first_result = search_response["certificates"][0]
            found_serial_id = first_result["serial_number"]
            raw_certificate = first_result["certificate"]
        except IndexError as e:
            return None, {"error": "No se encontraron certificados", "cause": e}
        except KeyError as e:
            return None, {"error": "No se encontro el certificado", "cause": e}
        if serial_id.upper() != found_serial_id.upper():
            return None, {
                "error": "El serial no coincide con el buscado",
                "original_serial": serial_id,
                "found_serial": found_serial_id,
            }

        try:
            certificate = self.certificate_decoder.from_raw(raw_certificate)
        except ValueError as e:
            return None, {"error": "Error al decodificar certificado", "cause": e}
        return certificate, None
