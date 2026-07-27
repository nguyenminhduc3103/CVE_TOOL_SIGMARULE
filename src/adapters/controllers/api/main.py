from fastapi import FastAPI
# TODO: wire FastAPI routes once `src/adapters/controllers/api/routes/triage.py` exists.
# from src.adapters.controllers.api.routes.triage import router as triage_router
from config import logging as logging_setup

app = FastAPI(title="CVE TI Platform")

# configure logging
logging_setup.configure()

# app.include_router(triage_router, prefix="/api/v1")

@app.get("/health")
async def health():
    return {"status": "ok"}
