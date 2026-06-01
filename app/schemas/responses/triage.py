from pydantic import BaseModel
from app.models.enriched import EnrichedCVEContext


class TriageResponse(BaseModel):
    data: EnrichedCVEContext
