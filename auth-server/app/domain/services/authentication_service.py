from pydantic import BaseModel
from app.interfaces.ejbca_client import EjbcaClient


class Certificate(BaseModel):
    serial_number: str
    status: str
    public_key: str
    
    
def validateCertificate(serial_number: str,
                      ejbca_client: EjbcaClient,
                      certificate_public_key_extractor: CPKY) -> dict:
    
    revocation_status = ejbca_client.getRevocationstatus(serial_number)
    
    if (revocation_status.revoked == True):
        logger.info(
            f"Certificate with serial number {serial_number} is revoked due to "
            f"{revocation_status.revocation_reason}."
        )
        return {"status": False}
    else:
        certificate = ejbca_client.getCertificate(serial_number)
        pub_key = certificate_public_key_extractor.getPemPublicKey(certificate)
        return {"status": True, "public_key": pub_key}
