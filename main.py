"""VibeLenz Safety Detection API"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
from datetime import datetime
from safety_detector import SafetyScamDetector
from models import MessageEvent

app = FastAPI(title="VibeLenz Safety API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

detector = SafetyScamDetector()

class Message(BaseModel):
    sender: str
    text: str
    timestamp: str = None

class AnalysisRequest(BaseModel):
    messages: List[Message]

@app.get("/")
def root():
    return {"service": "VibeLenz Safety API", "status": "operational"}

@app.post("/analyze")
def analyze_conversation(request: AnalysisRequest):
    try:
        messages = []
        for msg in request.messages:
            timestamp = msg.timestamp or datetime.now().isoformat()
            messages.append(MessageEvent(msg.sender, timestamp, msg.text))
        
        if len(messages) < 2:
            raise HTTPException(status_code=400, detail="Need 2+ messages")
        
        result = detector.analyze(messages)
        
        return {
            "risk_score": result.safety_risk_score,
            "risk_category": result.risk_category.value,
            "abort_recommended": result.abort_immediately_recommended,
            "flags": [
                {
                    "type": f.type.value,
                    "severity": f.severity,
                    "evidence": f.evidence,
                    "details": f.details
                }
                for f in result.active_flags
            ],
            "actions": result.recommended_actions,
            "explanation": result.explanation,
            "confidence": result.confidence
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
