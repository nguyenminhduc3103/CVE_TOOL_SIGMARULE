from fastapi import FastAPI
from app.api.routes import triage as triage_router
from app.core import logging as logging_setup

app = FastAPI(title="CVE TI Platform")

# configure logging
logging_setup.configure()

app.include_router(triage_router.router, prefix="/api/v1")

@app.get("/health")
async def health():
    return {"status": "ok"}
