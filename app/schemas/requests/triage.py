from pydantic import BaseModel


class TriageRequest(BaseModel):
    cve_id: str
