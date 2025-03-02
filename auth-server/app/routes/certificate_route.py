import logging

from app.application.authenticate_service import (AuthenticateService,
                                                  AuthResponse)
from app.clients.ejbca_client import EJBCAClient
from app.domain.entities.authorized_keys import AuthorizedKeysBuilder
from app.infrastucture.certificate_decoder import CertificateDecoder
from app.infrastucture.certificate_repository_impl import \
    CertificateRespositoryImpl
from app.main import get_config
from fastapi import APIRouter, Depends, HTTPException, status

router = APIRouter()


def get_authenticate_service(config: dict = Depends(get_config)) -> AuthenticateService:
    """Dependency function for injecting AuthenticateService."""
    ejbca_client = EJBCAClient(
        base_url=config["ejbca"]["base_url"],
        certificate_path=config["ejbca"]["certificate_path"],
        cert_password=config["ejbca"]["cert_password"],
    )
    certificate_decoder = CertificateDecoder()
    certificate_repository = CertificateRespositoryImpl(
        ejbca_client,
        certificate_decoder,
        config["ejbca"]["issuer_dn"],
    )
    authorized_keys_builder = AuthorizedKeysBuilder()
    return AuthenticateService(certificate_repository, authorized_keys_builder)


@router.get(
    "/certificate/{serial_id}/validate",
    tags=["certificate"],
    summary="Validate that certificate is not revoked",
    response_model=AuthResponse,
    responses={
        400: {"description": "Error al buscar el certificado."},
        403: {"description": "El certificado está revocado."},
        500: {"description": "Error interno. Contactar al administrador."},
    },
)
def validate(
    serial_id: str,
    username: str,
    service: AuthenticateService = Depends(get_authenticate_service),
):
    """Validates if the given certificate is revoked and returns authentication details."""
    try:
        auth_response, err = service.authenticate(serial_id, username)
        if err:
            logging.warning(
                "Validation failed for serial_id %s, error: %s",
                serial_id, err, extra={"serial_id": serial_id, "error": err}
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=err)

        if auth_response is None:
            logging.error(
                "Null response received for serial_id %s",
                serial_id, extra={"serial_id": serial_id}
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error interno. Contactar al administrador."
            )

        if auth_response.allowed:
            return auth_response

        logging.info("Certificate revoked for serial_id %s",
                     serial_id, extra={"serial_id": serial_id})
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="El certificado está revocado.")

    except KeyError as e:
        logging.exception("KeyError while processing serial_id %s", serial_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno. Contactar al administrador."
        ) from e

    except ValueError as e:
        logging.exception(
            "ValueError while processing serial_id %s", serial_id)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        ) from e

    except Exception as e:
        logging.exception(
            "Unexpected error while processing serial_id %s", serial_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error interno. Contactar al administrador."
        ) from e
