from functools import lru_cache
import logging
import os

from fastapi import FastAPI
from app.core.config.get_config import get_config
from app.routes.certificate_route import router as certificate_router

app = FastAPI(
    title="Certificate Validation API",
    description="Se usa esta API para validar que certificados emitidos por EJBCA son válidos. También permite verificar si un certificado ha sido revocado.",
    version="1.0.0",
    debug=True,
)
app.include_router(certificate_router, prefix="/api/v1")
try:
    get_config()
except Exception as e:
    logging.error("Error loading config: %s", e)
    raise e


@app.get("/healthcheck")
def healthcheck():
    return {"status": "ok"}
