# app.py
# VibeLenz - Verified Interaction Engine (VIE)
# FastAPI application layer - Railway deployment
# Precipice Social Intelligence LLC
# Copyright Ricky Sessums. All rights reserved.
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
import uuid
import os
from safety_detector import analyze_conversation
# ---------------------------------------------------------------------------
# APP INIT
# ---------------------------------------------------------------------------
app = FastAPI(
title="VibeLenz VIE API",
description="Verified Interaction Engine - Behavioral Safety Analysis",
version="1.0.0",
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
# ---------------------------------------------------------------------------
# SCHEMAS
# ---------------------------------------------------------------------------
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
# ---------------------------------------------------------------------------
# ROUTES
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def root():
"""Serve index.html if present, else return API status."""
index_path = os.path.join(os.path.dirname(__file__), "index.html")
if os.path.exists(index_path):
with open(index_path, "r") as f:
return HTMLResponse(content=f.read())
return HTMLResponse(content="<html><body><h2>VibeLenz VIE API - Running</h2><p>POST /anal
@app.get("/health", response_model=HealthResponse)
async def health():
"""Health check endpoint. Returns 200 if engine is operational."""
return {
"status": "operational",
"version": "1.0.0",
"engine": "vie.verifier.v2.0",
"fail_closed": True,
}
@app.post("/analyze")
async def analyze(request: AnalyzeRequest):
"""
Primary analysis endpoint.
Accepts conversation text, returns canonical VIE envelope.
Fail-closed: errors return WARN envelope, never raw exceptions.
"""
try:
result = analyze_conversation(
conversation_text=request.conversation,
conversation_id=request.conversation_id or str(uuid.uuid4()),
)
return JSONResponse(content=result, status_code=200)
except Exception as e:
fallback_id = request.conversation_id or str(uuid.uuid4())
return JSONResponse(
content={
"schema": "vie.envelope.v1",
"conversation_id": fallback_id,
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
"recommendations": [
{
"priority": "high",
"title": "Analysis Unavailable - Caution Advised",
"body": "Safety analysis could not be completed. Treat this conversat
}
],
},
status_code=200,
)
@app.get("/signals")
async def list_signals():
"""Returns the active signal library for partner integration."""
from safety_detector import SIGNAL_WEIGHTS, CRITICAL_SIGNALS, HIGH_SIGNALS, MEDIUM_SIGNAL
return {
"total_signals": len(SIGNAL_WEIGHTS),
"tiers": {
"critical": sorted(list(CRITICAL_SIGNALS)),
"high": sorted(list(HIGH_SIGNALS)),
"medium": sorted(list(MEDIUM_SIGNALS)),
}
}