import json
import logging
from math import log
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse

from app.application.authenticate_service import AuthResponse, AuthenticateService
from app.clients import ejbca_client
from app.domain.entities.authorized_keys import AuthorizedKeysBuilder
from app.domain.repositories import certificate_repository
from app.infrastucture import certificate_decoder
from app.infrastucture.certificate_repository_impl import CertificateRespositoryImpl
from pathlib import Path

router = APIRouter()
base_path = Path.cwd()
ejbca_client = ejbca_client.EJBCAClient(
    base_url="https://ejbca-bitnami_ejbca_1:8443/ejbca/ejbca-rest-api",
    key_path=f"{base_path}/auth-server/certs/certificate.pem",
    cert_password=f"{base_path}/auth-server/certs/private_key_no_passphrase.key",
)
certificate_decoder = certificate_decoder.CertificateDecoder()
certificate_repository = CertificateRespositoryImpl(ejbca_client, certificate_decoder)
authorized_keys_builder = AuthorizedKeysBuilder()
service = AuthenticateService(certificate_repository, authorized_keys_builder)


@router.get(
    "/certificate/{serial_id}/validate",
    tags=["certificate"],
    summary="Validate that certificate is not revoked",
    responses={
        200: {
            "description": "El certificado es válido y se permite el acceso.",
            "content": {
                "application/json": {
                    "example": AuthResponse(
                        allowed=True,
                        public_key="-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3foY/Og0/sAxGvG+/iow\nUwnkOFtuEuqaBHljKLilp9KEVjUlArY2Pf43Z5bc6kA/84g7I0W5NbikVsxoP8nx\nKtZrkZKZ7ws2ySKh58Wt5doTQyEu0UoXyP3GpTJMFL9OIWED0QTTmNWo3Qr1xX5V\nN4w59v36NiRl+e27DvRTPRHHtpflbikbj7i2/P5HCF3Q4Klr8PVKcMTB4P1P/vAZ\nZZ0nBEap81G/7mQlWWbkIN1w2BxI2HqVnGGbi44oq6bGkK9qF70fq9beQJQM3u3s\nBdm3IuvbFSQIAll6rDnZofb7hyNXCzrr+5pN8QoHoknt4SP24eC4u2Fefv1v95e+\n6QIDAQAB\n-----END PUBLIC KEY-----\n",
                    )
                }
            },
        },
        400: {
            "description": "Error al buscar el certificado.",
            "content": {
                "application/json": {
                    "example": AuthResponse(allowed=False, public_key=None)
                }
            },
        },
        403: {
            "description": "El certificado no tiene permisos para acceder porque esta revocado",
            "content": {
                "application/json": {
                    "example": AuthResponse(allowed=False, public_key=None)
                }
            },
        },
        500: {
            "description": "Error interno. Por favor contactarse con el administrador."
        },
    },
)
async def validate(serial_id: str, username: str):
    try:
        auth_response, err = service.authenticate(serial_id, username)
    except Exception as e:
        logging.error("Exception with validate. Serial_id %s", serial_id, exc_info=e)
        raise HTTPException(
            500, "Error interno. Por favor contactarse con el administrador."
        )
    if err is not None:
        logging.error(
            f"Error with validate. Serial_id %s. Err: {str(err)}",
            serial_id,
            exc_info=err,
        )
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=AuthResponse(allowed=False).model_dump(),
        )
    if auth_response is None:
        logging.error(f"auth_response vino nulo. serial_id: {serial_id}")
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            f"Error. Contactarse con el administrador",
        )

    if auth_response.allowed:
        return auth_response
    else:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=AuthResponse(allowed=False).model_dump(),
        )
