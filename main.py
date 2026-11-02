from fastapi import FastAPI, HTTPException
from .schemas import AssessmentRequest
from .scanner import assess

app = FastAPI(title="Web Security Posture API", version="1.0.0")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/assess")
async def create_assessment(request: AssessmentRequest):
    try:
        return await assess(str(request.url), request.timeout_seconds)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Assessment failed: {type(exc).__name__}")
