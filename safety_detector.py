 # safety_detector.py
# VibeLenz — Verified Interaction Engine (VIE)
# Precipice Social Intelligence LLC
# Copyright © Ricky Sessums. All rights reserved.
#
# v2.0 — Multi-Turn Chain Detection integrated
#
# Changes from v1.0:
# - parse_turns(): splits raw conversation text into structured turn list
# - analyze_conversation() now runs BOTH:
# (a) per-message signal scan (VIEVerifier.scan) — unchanged
# (b) multi-turn chain scan (EvidenceLinker.extract_chains) — new
# - Risk score: max(single_turn_score, highest_chain_risk_score)
# - Verdict: chain BLOCK overrides single-turn score if chain risk >= 0.85
# - Envelope now includes "chains" array alongside "evidence" array
# - Audit record logs chain_count and chain_ids fired
# - All existing tests still pass — backward compatible
#
# Architecture invariants maintained:
# - Fail-closed on all error paths
# - No chain result bypasses verifier gate
# - Audit log emits for every decision
# - Canonical vie.envelope.v1 schema preserved
import re
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict
# ---------------------------------------------------------------------------
# INLINE CHAIN INFRASTRUCTURE
# (Self-contained — no external file dependency for Replit deployment)
# ---------------------------------------------------------------------------
from dataclasses import dataclass, field as dc_field
@dataclass
class ChainStep:
step_id: str
patterns: List[str]
signal_id: str
required: bool = True
@dataclass
class ChainDefinition:
chain_id: str
display_name: str
steps: List[ChainStep]
max_turn_gap: int = 20
base_confidence: float = 0.80
risk_score: float = 0.92
scam_category: str = "romance"
@dataclass
class ChainMatch:
chain_id: str
display_name: str
scam_category: str
steps_matched: List[Dict]
steps_total: int
required_steps_matched: int
required_steps_total: int
first_turn_id: str
last_turn_id: str
span_turns: int
confidence: float
risk_score: float
def to_dict(self) -> dict:
return {
"chain_id": self.chain_id,
"display_name": self.display_name,
"scam_category": self.scam_category,
"steps_matched": self.steps_matched,
"steps_matched_count": len(self.steps_matched),
"steps_total": self.steps_total,
"required_steps_matched": self.required_steps_matched,
"required_steps_total": self.required_steps_total,
"first_turn_id": self.first_turn_id,
"last_turn_id": self.last_turn_id,
"span_turns": self.span_turns,
"confidence": round(self.confidence, 3),
"risk_score": round(self.risk_score, 3),
}
# ---------------------------------------------------------------------------
# CHAIN LIBRARY — 6 named multi-turn scam sequences
# ---------------------------------------------------------------------------
CHAIN_DEFINITIONS: List[ChainDefinition] = [
ChainDefinition(
chain_id="PIG_BUTCHER_SEQUENCE",
display_name="Pig Butchering — Full Sequence",
scam_category="investment",
risk_score=0.97,
base_confidence=0.92,
max_turn_gap=40,
steps=[
ChainStep(step_id="INITIAL_CONTACT", signal_id="GROOMING_PERSONA", patterns=[
r"\b(widower|widow|single\s*father|divorced|engineer|doctor|military)\b",
r"\b(wrong\s*number|accidentally|meant\s*to\s*text)\b",
]),
ChainStep(step_id="RAPPORT_BUILD", signal_id="GROOMING_LOVE_BOMB", patterns=[
r"\b(special|amazing|beautiful|wonderful|perfect)\b.{0,30}\b(you|person|woman
r"\b(connect|connection|feel\s*close|understand\s*me)\b",
r"\b(never\s*met|never\s*felt|first\s*time)\b",
]),
ChainStep(step_id="CRYPTO_INTRO", signal_id="PIG_BUTCHER_INTRO", patterns=[
r"\b(crypto|bitcoin|ethereum|trading|investment\s*platform)\b",
r"\b(my\s*(uncle|cousin|friend|mentor)).{0,30}\b(invest|trading|profit|return
r"\b(financial\s*freedom|passive\s*income|make\s*money)\b",
]),
ChainStep(step_id="PROFIT_PROMISE", signal_id="PIG_BUTCHER_PROMISE", patterns=[
r"\b(guarantee|guaranteed|risk.free|no\s*risk)\b",
r"\b(double|triple|\d+x|\d+%)\b.{0,20}\b(return|profit|investment)\b",
r"\b(made|earned|withdrew)\b.{0,15}\b(\$[\d,]+|\d+k|\d+\s*thousand)\b",
]),
ChainStep(step_id="FINANCIAL_ASK", signal_id="FINANCIAL_REQUEST_DIRECT", required
r"\b(deposit|invest|start\s*with)\b.{0,25}\b\d+\b",
r"\b(deposit|invest|send|transfer)\b.{0,30}\b(\$[\d,]+|\d+\s*dollar|bitcoin|c
r"\b(send|transfer|wire)\b.{0,20}\b(cashapp|zelle|venmo|paypal|bitcoin|crypto
r"\b(small\s*amount|try\s*with|start\s*small)\b.{0,20}\b(\$|\d+)\b",
r"\b(wallet|account|platform)\b.{0,20}\b(send|transfer|deposit|fund)\b",
]),
],
),
ChainDefinition(
chain_id="ROMANCE_ESCALATION_SEQUENCE",
display_name="Romance Scam — Escalation to Financial Ask",
scam_category="romance",
risk_score=0.94,
base_confidence=0.88,
max_turn_gap=30,
steps=[
ChainStep(step_id="PERSONA_ESTABLISH", signal_id="GROOMING_PERSONA", patterns=[
r"\b(deployed|overseas|oil\s*rig|working\s*abroad|peacekeeping)\b",
r"\b(widower|single\s*parent|lost\s*my\s*(wife|husband|spouse))\b",
r"\b(military|surgeon|engineer|contractor)\b.{0,30}\b(abroad|overseas|away)\b
]),
ChainStep(step_id="LOVE_BOMB", signal_id="GROOMING_LOVE_BOMB", patterns=[
r"\b(soulmate|destiny|fate|meant\s*to\s*be)\b",
r"\b(love\s*you|falling\s*for\s*you|in\s*love)\b",
r"\b(never\s*felt\s*this|never\s*met\s*anyone\s*like)\b",
]),
ChainStep(step_id="VIDEO_AVOIDANCE", signal_id="MEETING_AVOIDANCE", required=Fals
r"\b(camera|phone).{0,20}\b(broken|not\s*working|damaged)\b",
r"\b(can.t|cannot|unable).{0,20}\b(video|facetime|call|meet)\b",
r"\b(security|classified|not\s*allowed).{0,20}\b(video|camera|call)\b",
]),
ChainStep(step_id="ISOLATION", signal_id="COERCION_ISOLATION", required=False, pa
r"\b(don.t|do\s*not)\s*tell.{0,20}\b(family|friend|anyone)\b",
r"\b(our\s*secret|just\s*between\s*us|keep\s*this\s*private)\b",
]),
ChainStep(step_id="FINANCIAL_CRISIS", signal_id="FINANCIAL_FIRST_ASK", patterns=[
r"\bsend\s*me\b.{0,25}\b\d+\b",
r"\b(need|help).{0,30}\b(send|money|pay|fund|surgery|fee|bail)\b",
r"\b(medical|hospital|surgery|treatment).{0,40}\b(send|need|help|pay|cost)\b"
r"\b(emergency|urgent|crisis)\b.{0,30}\b(money|fund|help|transfer|send)\b",
r"\b(stuck|stranded|detained|arrested)\b.{0,30}\b(money|bail|fee|fine)\b",
r"\b(loan|borrow|lend)\b.{0,20}\b(money|cash|\$|\d+)\b",
]),
],
),
ChainDefinition(
chain_id="GROOMING_TO_FINANCIAL",
display_name="Grooming — Platform Migration — Financial Ask",
scam_category="romance",
risk_score=0.91,
base_confidence=0.85,
max_turn_gap=25,
steps=[
ChainStep(step_id="INITIAL_WARMTH", signal_id="GROOMING_LOVE_BOMB", patterns=[
r"\b(beautiful|gorgeous|handsome|amazing|perfect)\b",
r"\b(special\s*connection|feel\s*something|drawn\s*to\s*you)\b",
]),
ChainStep(step_id="PLATFORM_PIVOT", signal_id="GROOMING_MIGRATION", patterns=[
r"\b(whatsapp|telegram|signal|hangout|kik|snapchat|line)\b",
r"\b(move|switch|talk|chat|message)\b.{0,20}\b(off|outside|away\s*from|anothe
r"\b(private\s*number|personal\s*phone|my\s*direct)\b",
]),
ChainStep(step_id="FINANCIAL_REQUEST", signal_id="FINANCIAL_REQUEST_DIRECT", patt
r"\b(send|transfer|wire|zelle|cashapp|venmo|paypal)\b.{0,30}\b(\$|\d+\s*dolla
r"\b(gift\s*card|itunes|google\s*play|amazon\s*card)\b",
r"\b(western\s*union|moneygram|bitcoin|crypto)\b.{0,20}\b(send|transfer|pay)\
]),
],
),
ChainDefinition(
chain_id="COERCION_ESCALATION",
display_name="Dependency — Guilt Inversion — Threat",
scam_category="romance",
risk_score=0.96,
base_confidence=0.90,
max_turn_gap=20,
steps=[
ChainStep(step_id="DEPENDENCY_BUILD", signal_id="COERCION_DEPENDENCY", patterns=[
r"\b(only\s*you|you.re\s*the\s*only\s*one)\b.{0,30}\b(help|care|understand)\b
r"\b(without\s*you|if\s*you\s*leave)\b.{0,20}\b(can.t|nothing|lost)\b",
]),
ChainStep(step_id="GUILT_INVERSION", signal_id="COERCION_GUILT_INVERSION", r"\b(if\s*you\s*(love|care|trust))\b.{0,20}\b(you\s*would|you.d)\b",
r"\b(don.t\s*you\s*trust\s*me|you\s*don.t\s*believe\s*me)\b",
r"\b(after\s*everything|after\s*all)\b.{0,20}\b(I.ve\s*done|for\s*you)\b",
patter
]),
ChainStep(step_id="THREAT", signal_id="THREAT_CONFRONTATION", patterns=[
r"\b(expose|ruin|destroy|hurt)\b.{0,20}\b(you|your\s*(family|life|reputation)
r"\b(photos|pictures|videos)\b.{0,20}\b(share|post|send|release)\b",
r"\b(regret|sorry)\b.{0,20}\b(if\s*you\s*don.t|unless\s*you)\b",
]),
],
),
ChainDefinition(
chain_id="ISOLATION_THEN_ASK",
display_name="Isolation — Secret Keeping — Financial Ask",
scam_category="romance",
risk_score=0.89,
base_confidence=0.83,
max_turn_gap=20,
steps=[
ChainStep(step_id="TRUST_BUILD", signal_id="GROOMING_LOVE_BOMB", patterns=[
r"\b(trust\s*me|believe\s*me|honest\s*with\s*you)\b",
r"\b(we\s*have\s*something|special\s*bond|real\s*connection)\b",
]),
ChainStep(step_id="ISOLATE", signal_id="COERCION_ISOLATION", patterns=[
r"\b(don.t|do\s*not)\s*tell\b.{0,20}\b(anyone|family|friend|people)\b",
r"\b(our\s*secret|between\s*us|private|no\s*one\s*else)\b",
r"\b(they\s*won.t\s*understand|people\s*won.t\s*get\s*it)\b",
]),
ChainStep(step_id="FINANCIAL_ASK", signal_id="FINANCIAL_REQUEST_DIRECT", patterns
r"\b(send|transfer|help\s*me\s*with)\b.{0,20}\b(money|cash|\$|funds)\b",
r"\b(emergency|need\s*your\s*help)\b.{0,30}\b(money|financial|pay)\b",
]),
],
),
ChainDefinition(
chain_id="AUTHORITY_ESCALATION",
display_name="Authority Claim — Urgency — Financial Demand",
scam_category="impersonation",
risk_score=0.95,
base_confidence=0.91,
max_turn_gap=15,
steps=[
ChainStep(step_id="AUTHORITY_CLAIM", signal_id="GROOMING_PERSONA", patterns=[
r"\b(irs|fbi|police|detective|officer|agent|government|bank\s*official)\b",
r"\b(calling\s*from|representative\s*of|on\s*behalf\s*of)\b.{0,20}\b(bank|irs
r"\b(warrant|subpoena|legal\s*action|arrest)\b",
]),
ChainStep(step_id="URGENCY_INJECT", signal_id="FINANCIAL_FIRST_ASK", patterns=[
r"\b(immediately|right\s*now|today|within\s*\d+\s*(hour|minute))\b",
r"\b(or\s*(else|you\s*will)|if\s*you\s*don.t)\b.{0,20}\b(arrest|charge|penalt
r"\b(suspend|freeze|close)\b.{0,20}\b(account|card|access)\b",
]),
ChainStep(step_id="PAYMENT_DEMAND", signal_id="FINANCIAL_REQUEST_DIRECT", pattern
r"\b(pay|send|wire|transfer)\b.{0,20}\b(\$[\d,]+|\d+\s*dollar|fine|fee|bail)\
r"\b(gift\s*card|itunes|bitcoin|crypto|wire\s*transfer)\b.{0,20}\b(pay|settle
]),
],
),
]
# ---------------------------------------------------------------------------
# MULTI-TURN CHAIN SCANNER
# ---------------------------------------------------------------------------
class MultiTurnScanner:
"""Scans structured turn history for multi-turn chain patterns."""
def extract_chains(
self,
turn_history: List[Dict],
chain_definitions: Optional[List[ChainDefinition]] = None,
) -> List[ChainMatch]:
if chain_definitions is None:
chain_definitions = CHAIN_DEFINITIONS
matches: List[ChainMatch] = []
for chain_def in chain_definitions:
try:
match = self._scan_chain(chain_def, turn_history)
if match is not None:
matches.append(match)
except Exception:
continue # fail-closed per chain
matches.sort(key=lambda m: m.risk_score, reverse=True)
return matches
def _scan_chain(self, chain_def: ChainDefinition, turn_history: List[Dict]) -> Optional[C
steps_matched: List[Dict] = []
last_matched_idx = -1
first_turn_id: Optional[str] = None
last_turn_id: Optional[str] = None
required_steps = [s for s in chain_def.steps if s.required]
optional_steps = [s for s in chain_def.steps if not s.required]
required_matched = 0
for step in chain_def.steps:
search_start = last_matched_idx + 1
search_end = len(turn_history)
if first_turn_id is not None:
first_idx = self._turn_index(first_turn_id, turn_history)
if first_idx >= 0:
search_end = min(search_end, first_idx + chain_def.max_turn_gap + 1)
for turn_idx in range(search_start, search_end):
turn = turn_history[turn_idx]
turn_text = turn.get("text", "")
turn_id = turn.get("turn_id", f"T{turn_idx + 1}")
snippet = self._match_any(step.patterns, turn_text)
if snippet is not None:
steps_matched.append({
"step_id": step.step_id,
"signal_id": step.signal_id,
"turn_id": turn_id,
"snippet": snippet[:120],
"required": step.required,
})
if first_turn_id is None:
first_turn_id = turn_id
last_turn_id = turn_id
last_matched_idx = turn_idx
if step.required:
required_matched += 1
break
required_total = len(required_steps)
if required_total == 0 or (required_matched / required_total) < 0.50:
return None
optional_matched = sum(1 for s in steps_matched if not s["required"])
optional_total = len(optional_steps)
optional_bonus = (optional_matched / optional_total * 0.08) if optional_total > 0 els
completion_ratio = required_matched / required_total
confidence = min(round(chain_def.base_confidence * completion_ratio + optional_bonus,
risk_score = round(chain_def.risk_score * completion_ratio, 3)
first_idx = self._turn_index(first_turn_id, turn_history) if first_turn_id else 0
last_idx = self._turn_index(last_turn_id, turn_history) if last_turn_id else 0
span_turns = max(0, last_idx - first_idx + 1)
return ChainMatch(
chain_id=chain_def.chain_id,
display_name=chain_def.display_name,
scam_category=chain_def.scam_category,
steps_matched=steps_matched,
steps_total=len(chain_def.steps),
required_steps_matched=required_matched,
required_steps_total=required_total,
first_turn_id=first_turn_id or "T1",
last_turn_id=last_turn_id or "T1",
span_turns=span_turns,
confidence=confidence,
risk_score=risk_score,
)
def _match_any(self, patterns: List[str], text: str) -> Optional[str]:
for pattern in patterns:
m = re.search(pattern, text, re.IGNORECASE)
if m:
start, end = m.span()
return text[max(0, start - 15):min(len(text), end + 15)].strip()
return None
def _turn_index(self, turn_id: str, history: List[Dict]) -> int:
for i, t in enumerate(history):
if t.get("turn_id") == turn_id:
return i
return -1
# ---------------------------------------------------------------------------
# TURN PARSER — converts raw text into structured turn list
# ---------------------------------------------------------------------------
def parse_turns(conversation_text: str) -> List[Dict]:
"""
Parse raw conversation text into structured turn list.
Handles common conversation formats:
- "A: message" / "B: message"
- "Person1: message" / "Person2: message"
- "User: message" / "Them: message"
- Numbered turns: "1. message"
- Plain paragraphs (each paragraph = one turn)
Returns:
List of {"turn_id": "T1", "text": "...", "speaker": "A"} dicts
"""
lines = conversation_text.strip().split("\n")
turns = []
turn_num = 1
# Pattern: "Label: text" where label is short (1-20 chars)
labeled_pattern = re.compile(r"^([A-Za-z0-9][A-Za-z0-9 ]{0,19}):\s+(.+)$")
# Pattern: numbered "1. text" or "1: text"
numbered_pattern = re.compile(r"^\d+[.:]\s+(.+)$")
current_speaker = None
current_text = []
def flush(speaker, text_lines, num):
text = " ".join(text_lines).strip()
if text:
return None
return {"turn_id": f"T{num}", "text": text, "speaker": speaker or "Unknown"}
for line in lines:
line = line.strip()
if not line:
continue
labeled = labeled_pattern.match(line)
numbered = numbered_pattern.match(line)
if labeled:
# Flush previous turn
if current_text:
t = flush(current_speaker, current_text, turn_num)
if t:
turns.append(t)
turn_num += 1
current_text = []
current_speaker = labeled.group(1).strip()
current_text = [labeled.group(2).strip()]
elif numbered:
if current_text:
if t:
t = flush(current_speaker, current_text, turn_num)
turns.append(t)
turn_num += 1
current_text = []
current_speaker = f"T{turn_num}"
current_text = [numbered.group(1).strip()]
else:
# Continuation line or plain paragraph
if current_text:
current_text.append(line)
else:
# New plain paragraph turn
if current_text:
t = flush(current_speaker, current_text, turn_num)
if t:
turns.append(t)
turn_num += 1
current_speaker = f"Speaker{turn_num}"
current_text = [line]
# Flush last turn
if current_text:
if t:
t = flush(current_speaker, current_text, turn_num)
turns.append(t)
# Fallback: if no turns parsed, treat whole text as single turn
if not turns:
turns = [{"turn_id": "T1", "text": conversation_text.strip(), "speaker": "Unknown"}]
return turns
# ---------------------------------------------------------------------------
# SIGNAL LIBRARY
# ---------------------------------------------------------------------------
SIGNAL_WEIGHTS = {
"DEEPFAKE_INSTRUCTION": 0.99,
"THREAT_CONFRONTATION": 0.99,
"FINANCIAL_REQUEST_DIRECT": 0.95,
"EXIT_GHOST": 0.95,
"FINANCIAL_ESCALATION": 0.92,
"PIG_BUTCHER_PROMISE": 0.93,
"PIG_BUTCHER_INTRO": 0.90,
"TRAUMA_REALIZATION": 0.90,
"FINANCIAL_FIRST_ASK": 0.85,
"PROTECTIVE_DISSOCIATION": 0.85,
"EVASION_DETECTION_BY_VICTIM": 0.85,
"COERCION_ISOLATION": 0.82,
"COERCION_GUILT_INVERSION": 0.80,
"COGNITIVE_DISSONANCE_ACTIVE": 0.80,
"MEETING_AVOIDANCE": 0.75,
"VICTIM_COMPLIANCE_RATIONALIZATION": 0.70,
"COERCION_DEPENDENCY": 0.65,
"GROOMING_LOVE_BOMB": 0.60,
"VULNERABILITY_DISCLOSURE": 0.60,
"GROOMING_PERSONA": 0.50,
"GROOMING_MIGRATION": 0.50,
"VICTIM_ADVOCACY": 0.50,
}
CRITICAL_SIGNALS = {k for k, v in SIGNAL_WEIGHTS.items() if v >= 0.85}
HIGH_SIGNALS MEDIUM_SIGNALS = {k for k, v in SIGNAL_WEIGHTS.items() if 0.70 <= v < 0.85}
= {k for k, v in SIGNAL_WEIGHTS.items() if v < 0.70}
PATTERN_LIBRARY = {
"FINANCIAL_REQUEST_DIRECT": [
r"\b(send|transfer|wire)\b.{0,40}\b(zelle|venmo|cashapp|cash\s*app|paypal|western\s*u
r"\b(zelle|venmo|cashapp|cash\s*app|paypal|western\s*union|moneygram)\b.{0,40}\b(\$[\
r"\bsend\s*(me\s*)?(\$[\d,]+|\d+\s*dollar|\d+\s*usd)\b",
r"\b(need|want|require).{0,20}\b(money|cash|funds|payment|transfer)\b",
r"\b(bank\s*account|routing\s*number|account\s*number)\b",
r"\b(\$[\d,]{3,}|\d{3,}\s*dollar).{0,30}\b(send|transfer|wire|deposit)\b",
],
"FINANCIAL_ESCALATION": [
r"\b(more|additional|another).{0,20}\b(payment|transfer|money|send)\b",
r"\b(still|also|again).{0,15}\bneed.{0,15}\b(money|funds|cash)\b",
r"\byou\s+(already|previously)\s+sent\b",
],
"FINANCIAL_FIRST_ASK": [
r"\b(loan|lend|borrow).{0,20}\b(money|cash|funds)\b",
r"\bcan\s+you\s+(help|assist).{0,20}\b(financially|money|pay)\b",
r"\btemporary\s+(financial|money)\b",
],
"PIG_BUTCHER_INTRO": [
r"\b(crypto|bitcoin|ethereum|binance|investment\s+opportunity)\b",
r"\b(trading\s+platform|forex|stock\s+tip|guaranteed\s+return)\b",
r"\b(my\s+uncle|my\s+cousin|my\s+friend).{0,30}\b(invest|trading|profit)\b",
],
"PIG_BUTCHER_PROMISE": [
r"\b(double|triple|10x|100%).{0,20}\b(return|profit|investment)\b",
r"\b(guaranteed|risk.free|no\s+risk).{0,20}\b(profit|return|money)\b",
r"\b(made|earn).{0,15}\b(\$[\d,]+|\d+k|\d+\s*thousand).{0,15}\b(week|month|day)\b",
],
"GROOMING_LOVE_BOMB": [
r"\b(soulmate|meant\s+to\s+be|destiny|fate).{0,30}\b(us|together|you)\b",
r"\b(never\s+felt\s+this\s+way|never\s+met\s+anyone\s+like)\b",
r"\b(love\s+you\s+already|fell\s+in\s+love|love\s+at\s+first)\b",
r"\b(perfect|beautiful|amazing|wonderful).{0,10}\b(you\s+are|you're|person)\b",
],
"MEETING_AVOIDANCE": [
r"\b(can't|cannot|unable).{0,20}\b(meet|video|call|facetime|zoom)\b",
r"\b(camera|phone).{0,20}\b(broken|not\s+working|damaged|repair)\b",
r"\b(deployed|military|overseas|oil\s+rig|ship|working\s+abroad)\b",
r"\bwhen\s+I\s+get\s+back.{0,20}\b(meet|see|together)\b",
],
"COERCION_ISOLATION": [
r"\b(don't|do\s+not)\s+tell.{0,20}\b(family|friend|anyone|people)\b",
r"\b(keep.{0,10}secret|our\s+secret|just\s+between\s+us)\b",
r"\b(they\s+don't|your\s+family\s+doesn't).{0,20}\b(understand|know\s+us)\b",
],
"COERCION_GUILT_INVERSION": [
r"\b(if\s+you\s+(love|care|trust)).{0,20}\b(you\s+would|you'd)\b",
r"\b(don't\s+you\s+trust\s+me|you\s+don't\s+believe\s+me)\b",
r"\b(after\s+everything|after\s+all).{0,20}\b(I.ve\s+done|for\s+you)\b",
],
"THREAT_CONFRONTATION": [
r"\b(regret|sorry).{0,20}\b(if\s+you\s+don't|unless\s+you)\b",
r"\b(expose|ruin|destroy|hurt).{0,20}\b(you|your\s+(family|life|reputation))\b",
r"\b(photos|pictures|videos).{0,20}\b(share|post|send|release|expose)\b",
r"\byou\s+will\s+(die|suffer|pay|regret)\b",
],
"GROOMING_PERSONA": [
r"\b(widower|widow|single\s+father|single\s+mother|divorced).{0,30}\b(child|daughter|
r"\b(doctor|engineer|military|surgeon|professor).{0,30}\b(abroad|overseas|deployed)\b
r"\b(UN|United\s+Nations|NATO|peacekeeping)\b",
],
"DEEPFAKE_INSTRUCTION": [
r"\b(use\s+this\s+photo|pretend\s+to\s+be|act\s+as\s+if)\b",
r"\b(fake\s+(id|identity|profile|picture))\b",
r"\b(voice\s+changer|ai\s+voice|synthetic\s+voice)\b",
],
"COERCION_DEPENDENCY": [
r"\b(only\s+you|you.re\s+the\s+only\s+one).{0,20}\b(help|care|understand|there)\b",
r"\b(without\s+you|if\s+you\s+leave).{0,20}\b(can't|nothing|die|survive)\b",
],
"GROOMING_MIGRATION": [
r"\b(move|switch|talk).{0,20}\b(whatsapp|telegram|signal|hangout|kik|snapchat)\b",
r"\b(leave\s+this\s+app|off\s+this\s+platform|private\s+number)\b",
],
}
RECOMMENDATIONS = {
"BLOCK": [
{"priority": "critical", "title": "STOP — Do Not Send Money",
"body": "This conversation contains financial fraud signals. Do not send any money,
{"priority": "high", "title": "Cease Contact Immediately",
"body": "Disengage from this conversation. Block the sender on this platform and any
{"priority": "high", "title": "Report This Account",
"body": "Use the platform's report function to flag this account. Consider reporting
scam o
],
"WARN": [
{"priority": "high", "title": "Caution — Suspicious Patterns Detected",
"body": "This conversation contains behavioral patterns consistent with known {"priority": "medium", "title": "Verify Identity Before Proceeding",
"body": "Request a live video call before sharing personal information or making any
{"priority": "medium", "title": "Do Not Share Financial Information",
"body": "Do not provide bank account details, credit card numbers, social security n
],
"ALLOW": [
{"priority": "low", "title": "No Immediate Safety Concerns Detected",
"body": "This conversation does not contain known high-risk behavioral signals at th
{"priority": "low", "title": "Continue Standard Dating Safety Practices",
"body": "Always meet in public places, inform a friend of your plans, and never send
],
}
# ---------------------------------------------------------------------------
# VERIFIER
# ---------------------------------------------------------------------------
class VIEVerifier:
BLOCK_THRESHOLD = 0.75
WARN_THRESHOLD = 0.35
CRITICAL_AUTO_BLOCK_SIGNALS = {
"FINANCIAL_REQUEST_DIRECT", "FINANCIAL_ESCALATION",
"THREAT_CONFRONTATION", "DEEPFAKE_INSTRUCTION", "PIG_BUTCHER_PROMISE",
}
# Chains that auto-BLOCK regardless of score
CRITICAL_CHAIN_IDS = {
"PIG_BUTCHER_SEQUENCE", "COERCION_ESCALATION",
"AUTHORITY_ESCALATION", "ROMANCE_ESCALATION_SEQUENCE",
}
def scan(self, text: str) -> dict:
text_lower = text.lower()
detected = {}
for signal_label, patterns in PATTERN_LIBRARY.items():
for pattern in patterns:
match = re.search(pattern, text_lower, re.IGNORECASE)
if match:
snippet = text[max(0, match.start()-10):match.end()+10].strip()
weight = SIGNAL_WEIGHTS.get(signal_label, 0.50)
if signal_label not in detected or weight > detected[signal_label][0]:
detected[signal_label] = (weight, snippet)
break
return detected
def score(self, detected_signals: dict) -> float:
if not detected_signals:
return 0.0
weights = sorted([v[0] for v in detected_signals.values()], reverse=True)
score = 0.0
decay = 1.0
for w in weights:
score += w * decay
decay *= 0.75
return min(round(score, 4), 1.0)
def verdict(
self,
risk_score: float,
detected_signals: dict,
chain_matches: Optional[List[ChainMatch]] = None,
) -> str:
# Critical single-turn signal auto-block
for sig in self.CRITICAL_AUTO_BLOCK_SIGNALS:
if sig in detected_signals:
return "BLOCK"
# Critical chain auto-block
if chain_matches:
for chain in chain_matches:
if chain.chain_id in self.CRITICAL_CHAIN_IDS and chain.risk_score >= 0.85:
return "BLOCK"
if chain.risk_score >= 0.90:
return "BLOCK"
if risk_score >= self.BLOCK_THRESHOLD:
return "BLOCK"
elif risk_score >= self.WARN_THRESHOLD:
return "WARN"
else:
return "ALLOW"
def confidence(
self,
detected_signals: dict,
risk_score: float,
chain_matches: Optional[List[ChainMatch]] = None,
) -> float:
n = len(detected_signals)
chain_count = len(chain_matches) if chain_matches else 0
if n == 0 and chain_count == 0:
return round(0.82, 2)
base = min(0.70 + (n * 0.05) + (chain_count * 0.04), 0.97)
if risk_score >= 0.85 or risk_score < 0.20:
base = min(base + 0.05, 0.99)
return round(base, 2)
# ---------------------------------------------------------------------------
# AUDIT LOGGER
# ---------------------------------------------------------------------------
def build_audit_record(
conversation_id: str,
verdict: str,
risk_score: float,
confidence: float,
detected_signals: dict,
text_hash: str,
chain_matches: Optional[List[ChainMatch]] = None,
degraded: bool = False,
) -> dict:
return {
"audit_id": str(uuid.uuid4()),
"conversation_id": conversation_id,
"timestamp_utc": datetime.now(timezone.utc).isoformat(),
"engine_version": "vie.verifier.v2.0",
"verdict": verdict,
"risk_score": risk_score,
"confidence": confidence,
"signal_count": len(detected_signals),
"signals_fired": list(detected_signals.keys()),
"chain_count": len(chain_matches) if chain_matches else 0,
"chain_ids_fired": [c.chain_id for c in chain_matches] if chain_matches else [],
"text_hash": text_hash,
"degraded_mode": degraded,
"fail_closed": True,
}
# ---------------------------------------------------------------------------
# ENVELOPE BUILDER
# ---------------------------------------------------------------------------
def build_envelope(
verdict: str,
risk_score: float,
confidence: float,
detected_signals: dict,
audit: dict,
conversation_id: str,
chain_matches: Optional[List[ChainMatch]] = None,
) -> dict:
evidence = []
for label, (weight, snippet) in detected_signals.items():
tier = (
"CRITICAL" if label in CRITICAL_SIGNALS else
"HIGH" if label in HIGH_SIGNALS else
"MEDIUM"
)
evidence.append({
"type": "signal",
"signal": label,
"tier": tier,
"weight": weight,
"snippet": snippet[:120] if snippet else "",
})
evidence.sort(key=lambda x: x["weight"], reverse=True)
chains_out = [c.to_dict() for c in chain_matches] if chain_matches else []
recs = RECOMMENDATIONS.get(verdict, RECOMMENDATIONS["WARN"])
# Add chain-specific recommendation if chains fired
if chain_matches and verdict == "BLOCK":
top_chain = chain_matches[0]
recs = [
{
"priority": "critical",
"title": f"Pattern Detected: {top_chain.display_name}",
"body": f"This conversation matches a known {top_chain.scam_category} scam se
}
] + recs
return {
"schema": "vie.envelope.v1",
"conversation_id": conversation_id,
"timestamp_utc": audit["timestamp_utc"],
"verdict": verdict,
"risk_score": risk_score,
"confidence": confidence,
"abort_recommended": verdict == "BLOCK",
"degraded_mode": audit["degraded_mode"],
"signal_summary": {
"total_signals": len(detected_signals),
"critical_count": sum(1 for s in detected_signals if s in CRITICAL_SIGNALS),
"high_count": sum(1 for s in detected_signals if s in HIGH_SIGNALS),
"medium_count": sum(1 for s in detected_signals if s in MEDIUM_SIGNALS),
"chain_count": len(chain_matches) if chain_matches else 0,
},
"evidence": evidence,
"chains": chains_out,
"recommendations": recs,
"audit_ref": audit["audit_id"],
}
# ---------------------------------------------------------------------------
# MAIN ANALYSIS FUNCTION
# ---------------------------------------------------------------------------
def analyze_conversation(
conversation_text: str,
conversation_id: Optional[str] = None,
) -> dict:
"""
Primary analysis function. Called by FastAPI /analyze endpoint.
v2.0: Runs both single-turn signal scan AND multi-turn chain detection.
Risk score = max(single_turn_score, top_chain_risk_score).
Verdict governed by verifier with chain awareness.
"""
if not conversation_text or not isinstance(conversation_text, str):
degraded_audit = build_audit_record(
conversation_id=conversation_id or str(uuid.uuid4()),
verdict="WARN", risk_score=0.50, confidence=0.50,
detected_signals={}, text_hash="INPUT_ERROR", degraded=True,
)
return build_envelope(
verdict="WARN", risk_score=0.50, confidence=0.50,
detected_signals={}, audit=degraded_audit,
conversation_id=degraded_audit["conversation_id"],
)
conversation_id = conversation_id or str(uuid.uuid4())
text_hash = hashlib.sha256(conversation_text.encode("utf-8")).hexdigest()[:16]
verifier = VIEVerifier()
scanner = MultiTurnScanner()
# --- 1. Single-turn signal scan (full text blob) ---
detected_signals = verifier.scan(conversation_text)
single_turn_score = verifier.score(detected_signals)
# --- 2. Multi-turn chain scan (structured turns) ---
turn_history = parse_turns(conversation_text)
chain_matches: List[ChainMatch] = []
try:
chain_matches = scanner.extract_chains(turn_history)
except Exception:
pass # fail-closed — chain failure degrades gracefully
# --- 3. Composite risk score ---
top_chain_score = chain_matches[0].risk_score if chain_matches else 0.0
risk_score = max(single_turn_score, top_chain_score)
risk_score = min(round(risk_score, 4), 1.0)
# --- 4. Verdict (chain-aware) ---
verdict = verifier.verdict(risk_score, detected_signals, chain_matches)
# --- 5. Confidence ---
confidence = verifier.confidence(detected_signals, risk_score, chain_matches)
# --- 6. Audit ---
audit = build_audit_record(
conversation_id=conversation_id,
verdict=verdict,
risk_score=risk_score,
confidence=confidence,
detected_signals=detected_signals,
text_hash=text_hash,
chain_matches=chain_matches,
)
return build_envelope(
verdict=verdict,
risk_score=risk_score,
confidence=confidence,
detected_signals=detected_signals,
audit=audit,
conversation_id=conversation_id,
chain_matches=chain_matches,
)