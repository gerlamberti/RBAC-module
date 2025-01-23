import logging
from typing import Union

from fastapi import FastAPI
from app.routes.certificate_route import router as certificate_router 
app = FastAPI(
    title="Certificate Validation API",
    description="Se usa esta API para validar que certificados emitidos por EJBCA son válidos. También permite verificar si un certificado ha sido revocado.",
    version="1.0.0",
    debug=True,
)

app.include_router(certificate_router, prefix="/api/v1")

@app.get("/")
def read_root():
    return {"Hello": "123Wofrflsdfdff"}
