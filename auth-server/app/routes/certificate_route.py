import logging
from math import log
from fastapi import APIRouter, HTTPException, status

from app.application.authenticate_service import AuthenticateService
from app.clients import ejbca_client
from app.domain.repositories import certificate_repository
from app.infrastucture import certificate_decoder
from app.infrastucture.certificate_repository_impl import CertificateRespositoryImpl
from pathlib import Path

router = APIRouter()
base_path = Path.cwd()
ejbca_client = ejbca_client.EJBCAClient(
    base_url="https://ejbca:8443/ejbca/ejbca-rest-api",
    key_path=f"{base_path}/auth-server/certs/certificate.pem",
    cert_password=f"{base_path}/auth-server/certs/private_key_no_passphrase.key",
)
certificate_decoder = certificate_decoder.CertificateDecoder()
certificate_repository = CertificateRespositoryImpl(ejbca_client, certificate_decoder)
service = AuthenticateService(certificate_repository)


@router.get(
    "/certificate/{serial_id}/validate",
    tags=["certificate"],
    summary="Validate that certificate is not revoked",
)
async def validate(serial_id: str):
    try:
        auth_response, err = service.authenticate(serial_id)
    except Exception as e:
        if err is not None:
            logging.error("Error with validate. Serial_id %s", serial_id, exc_info=err)
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Error al buscar el certificado.")
        logging.error("Exception with validate. Serial_id %s", serial_id, exc_info=e)
        raise HTTPException(
            500, "Error interno. Por favor contactarse con el administrador."
        )
    if (auth_response and auth_response.allowed):
        return auth_response
    else:
        raise HTTPException(status.HTTP_403_FORBIDDEN, auth_response)
