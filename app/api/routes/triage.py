from fastapi import APIRouter, HTTPException
from app.triage.orchestrator import TriageOrchestrator
from app.schemas.requests.triage import TriageRequest
from app.schemas.responses.triage import TriageResponse

router = APIRouter()


@router.post("/triage", response_model=TriageResponse, response_model_exclude_none=True)
async def triage(request: TriageRequest):
    orchestrator = TriageOrchestrator()
    try:
        result = await orchestrator.orchestrate(request.cve_id)
        return TriageResponse(data=result)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
