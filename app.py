# app.py

try:
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ModuleNotFoundError:
    FASTAPI_AVAILABLE = False

if not FASTAPI_AVAILABLE:
    print("FastAPI is not available in Pythonista.")
    print("This file is for server deployment, not local Pythonista use.")
    print("Use the Pythonista scam checker script instead.")
else:
    from typing import Optional
    import uuid
    import os

    from safety_detector import (
        analyze_conversation,
        SIGNAL_WEIGHTS,
        CRITICAL_SIGNALS,
        HIGH_SIGNALS,
        MEDIUM_SIGNALS,
    )

    app = FastAPI(
        title="VibeLenz VIE API",
        description="Verified Interaction Engine - Behavioral Safety Analysis",
        version="2.1.0",
        docs_url="/docs",
        redoc_url=None,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    class AnalyzeRequest(BaseModel):
        conversation: str = Field(
            ...,
            min_length=1,
            max_length=50000,
            description="Raw conversation text to analyze",
        )
        conversation_id: Optional[str] = Field(
            default=None,
            description="Optional caller-supplied conversation ID",
        )

    class HealthResponse(BaseModel):
        status: str
        version: str
        engine: str
        fail_closed: bool

    @app.get("/", response_class=HTMLResponse)
    async def root():
        index_path = os.path.join(os.path.dirname(__file__), "index.html")
        if os.path.exists(index_path):
            with open(index_path, "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read())

        return HTMLResponse(
            content=(
                "<html><body>"
                "<h2>VibeLenz VIE API v2.1 - Running</h2>"
                "<p>POST /analyze to analyze a conversation.</p>"
                "<p><a href='/docs'>API Docs</a></p>"
                "</body></html>"
            )
        )

    @app.get("/health", response_model=HealthResponse)
    async def health():
        return {
            "status": "operational",
            "version": "2.1.0",
            "engine": "VIE-deterministic-v2.1",
            "fail_closed": True,
        }

    @app.get("/ping")
    async def ping():
        return {"pong": True}

    @app.post("/analyze")
    async def analyze(request: AnalyzeRequest):
        cid = request.conversation_id or str(uuid.uuid4())

        try:
            result = analyze_conversation(
                conversation_text=request.conversation,
                conversation_id=cid,
            )
            return JSONResponse(content=result, status_code=200)

        except Exception:
            return JSONResponse(
                content={
                    "schema": "vie.envelope.v1",
                    "conversation_id": cid,
                    "verdict": "WARN",
                    "risk_score": 0.50,
                    "confidence": 0.50,
                    "abort_recommended": False,
                    "degraded_mode": True,
                    "error": "INTERNAL_ENGINE_ERROR",
                    "signal_summary": {
                        "total_signals": 0,
                        "critical_count": 0,
                        "high_count": 0,
                        "medium_count": 0,
                    },
                    "evidence": [],
                    "chains": [],
                    "recommendations": [
                        {
                            "priority": "high",
                            "title": "Analysis Unavailable",
                            "body": "Safety analysis failed. Treat this conversation with caution.",
                        }
                    ],
                },
                status_code=200,
            )

    @app.get("/signals")
    async def list_signals():
        return {
            "total_signals": len(SIGNAL_WEIGHTS),
            "tiers": {
                "critical": sorted(list(CRITICAL_SIGNALS)),
                "high": sorted(list(HIGH_SIGNALS)),
                "medium": sorted(list(MEDIUM_SIGNALS)),
            },
        }