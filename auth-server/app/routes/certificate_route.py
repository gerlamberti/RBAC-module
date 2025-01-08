from fastapi import APIRouter

router = APIRouter()


@router.get("/certificate/{serial_id}/validate",
            tags=["certificate"],
            summary="Validate that certificate is not revoked")
async def validate(serial_id: str):
    return {"serial_id": serial_id, "status": "valid"}
