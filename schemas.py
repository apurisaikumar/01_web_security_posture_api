from pydantic import BaseModel, Field, HttpUrl

class AssessmentRequest(BaseModel):
    url: HttpUrl
    timeout_seconds: int = Field(default=8, ge=2, le=15)

class Finding(BaseModel):
    id: str
    title: str
    severity: str
    evidence: str
    recommendation: str

class AssessmentResult(BaseModel):
    target: str
    status_code: int
    final_url: str
    findings: list[Finding]
    counts: dict[str, int]
