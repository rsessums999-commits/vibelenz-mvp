"""
Safety & Scam Detection Engine
Enhanced with real-world Reddit conversation patterns
Pythonista-compatible version
"""
import re
from datetime import timedelta
from models import (
    MessageEvent, SafetyFlag, SafetyFlagType, 
    SafetyAnalysisOutput, RiskCategory, SenderRole
)

# Risk weights
SAFETY_RISK_WEIGHTS = {
    SafetyFlagType.MONEY_REQUEST: 0.85,
    SafetyFlagType.EARLY_PRIVATE_MEETING: 0.70,
    SafetyFlagType.LOVE_BOMBING: 0.45,
}

ABORT_TRIGGERS = {SafetyFlagType.MONEY_REQUEST}


class SafetyScamDetector:
    """Detect financial exploitation, unsafe meetups, manipulation"""
    
    def analyze(self, messages: list) -> SafetyAnalysisOutput:
        """Run full safety analysis"""
        flags = []
        
        # Run detection modules
        flags.extend(self._detect_money_requests(messages))
        flags.extend(self._detect_early_meetup_pressure(messages))
        flags.extend(self._detect_love_bombing(messages))
        
        # Compute risk
        risk_score = self._compute_risk_score(flags)
        risk_category = self._categorize_risk(risk_score)
        abort = self._should_abort_immediately(flags)
        
        return SafetyAnalysisOutput(
            risk_score=risk_score,
            risk_category=risk_category,
            abort_flag=abort,
            flags=flags,
            confidence=self._compute_confidence(flags, messages),
            actions=self._generate_actions(flags, risk_category),
            explanation=self._generate_explanation(flags, risk_score)
        )
    
    def _detect_money_requests(self, messages: list) -> list:
        """Detect money requests and crypto scams"""
        flags = []
        
        # Enhanced money request patterns from real Reddit examples
        money_patterns = [
            r'\b(can|could) you (send|wire|transfer|lend|venmo|cashapp|zelle)\b',
            r'\bneed.*(\$|money|cash|help.*pay)\b',
            r'\b(venmo|cashapp|zelle|paypal)\s+me\b',
            r'\bemergency.*\$\d+\b',
            r'\bshort on (rent|bills|cash|gas)\b',
            r'\bcard.*declined\b',
            r'\bstuck (here|at|and)\b.*\$',
            r'\bpay you back (double|triple|later)\b',
            r'\bjust need like \$\d+\b',
        ]
        
        # Enhanced crypto patterns from real examples
        crypto_patterns = [
            r'\b(crypto|bitcoin|ethereum|trading platform|nodes)\b',
            r'\binvestment opportunity\b',
            r'\bguaranteed returns\b',
            r'\bmy (aunt|uncle|cousin|friend) taught me\b.*\b(trade|crypto|invest)\b',
            r'\bmade \$\d+.*this (morning|week|month)\b',
            r'\bpassive income\b',
            r'\bdownload.*app\b.*(trade|invest|crypto)',
            r'\bwant to be wealthy together\b',
        ]
        
        # Urgency indicators that boost severity
        urgency_terms = ['stuck', 'stranded', 'embarrassed', 'stressed', 
                        'right now', 'urgent', 'asap', 'please', 'crisis']
        
        for i, msg in enumerate(messages):
            if msg.sender_role != SenderRole.PARTNER:
                continue
            
            text_lower = msg.text.lower()
            
            # Check money requests
            for pattern in money_patterns:
                if re.search(pattern, text_lower):
                    amount_match = re.search(r'\$(\d+)', msg.text)
                    amount = amount_match.group(0) if amount_match else None
                    
                    # Check for urgency language
                    urgency = any(term in text_lower for term in urgency_terms)
                    
                    # Check for "pay you back" promise
                    payback_promise = bool(re.search(r'\bpay you back\b', text_lower))
                    
                    flags.append(SafetyFlag(
                        flag_type=SafetyFlagType.MONEY_REQUEST,
                        severity="HIGH",
                        details={
                            "amount": amount,
                            "urgency": urgency,
                            "payback_promise": payback_promise,
                            "message_number": i + 1
                        },
                        evidence=f"Money request in message #{i+1}: '{msg.text[:80]}...'"
                    ))
                    break
            
            # Check crypto scams
            for pattern in crypto_patterns:
                if re.search(pattern, text_lower):
                    flags.append(SafetyFlag(
                        flag_type=SafetyFlagType.MONEY_REQUEST,
                        severity="HIGH",
                        details={
                            "scam_type": "crypto_investment",
                            "message_number": i + 1
                        },
                        evidence=f"Crypto/investment scam in message #{i+1}: '{msg.text[:80]}...'"
                    ))
                    break
        
        return flags
    
    def _detect_early_meetup_pressure(self, messages: list) -> list:
        """Detect unsafe meetup pressure with gaslighting detection"""
        flags = []
        
        if len(messages) < 20:
            # Enhanced meetup patterns from real examples
            meetup_patterns = [
                r'\bcome over\b',
                r'\bcome to my place\b',
                r'\bmy place\b',
                r'\bmy apartment\b',
                r'\bcome through\b',
                r'\blet\'?s meet\b',
                r'\bwanna hang\b',
                r'\bwine and netflix\b',
            ]
            
            # Gaslighting/manipulation patterns from real examples
            gaslighting_patterns = [
                r'\bwhy are you being (so )?(difficult|paranoid|a prude)\b',
                r'\bdon\'t be (so )?(difficult|a prude|like that)\b',
                r'\b(parks|coffee shops) are boring\b',
                r'\bjust come over\b',
                r'\bit\'s way more comfortable\b',
            ]
            
            for i, msg in enumerate(messages):
                if msg.sender_role != SenderRole.PARTNER:
                    continue
                
                text_lower = msg.text.lower()
                
                # Check for meetup pressure
                for pattern in meetup_patterns:
                    if re.search(pattern, text_lower):
                        private = bool(re.search(r'\b(my place|my apartment|come over|come to my)\b', text_lower))
                        
                        # Check if this message also contains gaslighting
                        has_gaslighting = any(re.search(p, text_lower) for p in gaslighting_patterns)
                        
                        flags.append(SafetyFlag(
                            flag_type=SafetyFlagType.EARLY_PRIVATE_MEETING,
                            severity="HIGH" if (private or has_gaslighting) else "MEDIUM",
                            details={
                                "messages_before_request": len(messages),
                                "private_location": private,
                                "gaslighting_detected": has_gaslighting
                            },
                            evidence=f"Unsafe meetup pressure in message #{i+1}: '{msg.text[:80]}...'"
                        ))
                        break
        
        return flags
    
    def _detect_love_bombing(self, messages: list) -> list:
        """Detect excessive early intimacy"""
        flags = []
        
        if len(messages) < 2:
            return flags
        
        timespan = messages[-1].timestamp - messages[0].timestamp
        days = timespan.total_seconds() / 86400
        
        partner_msgs = [m for m in messages if m.sender_role == SenderRole.PARTNER]
        
        # Check for premature intimacy (enhanced with real examples)
        if days < 7 or len(messages) < 30:
            intimacy_patterns = [
                r'\blove you\b',
                r'\bsoulmate\b',
                r'\bmeant to be\b',
                r'\bperfect for each other\b',
                r'\bnever felt.*connection like this\b',
                r'\bimagining our (wedding|future|life together)\b',
                r'\bdeleting the app.*nobody else\b',
                r'\bwhen you know,? you know\b',
            ]
            
            intimacy_count = sum(
                1 for msg in partner_msgs
                if any(re.search(p, msg.text.lower()) for p in intimacy_patterns)
            )
            
            if intimacy_count > 0:
                flags.append(SafetyFlag(
                    flag_type=SafetyFlagType.LOVE_BOMBING,
                    severity="MEDIUM" if intimacy_count == 1 else "HIGH",
                    details={
                        "intimacy_count": intimacy_count,
                        "days_elapsed": round(days, 1),
                        "hours_since_match": round(days * 24, 1)
                    },
                    evidence=f"Love bombing: {intimacy_count} intimate declarations in {round(days, 1)} days"
                ))
        
        # Check for excessive compliments (lowered threshold from real data)
        if len(partner_msgs) >= 5:  # Changed from 10 to 5
            compliment_patterns = [
                r'\bbeautiful\b',
                r'\bgorgeous\b',
                r'\bperfect\b',
                r'\bamazing\b',
                r'\bstunning\b',
                r'\bincredible\b',
                r'\bsexy\b',
            ]
            
            compliment_count = 0
            for msg in partner_msgs[:20]:
                text_lower = msg.text.lower()
                for pattern in compliment_patterns:
                    if re.search(pattern, text_lower):
                        compliment_count += 1
            
            if compliment_count >= 5:
                flags.append(SafetyFlag(
                    flag_type=SafetyFlagType.LOVE_BOMBING,
                    severity="MEDIUM",
                    details={
                        "compliment_count": compliment_count,
                        "in_first_n_messages": min(20, len(partner_msgs))
                    },
                    evidence=f"Excessive compliments ({compliment_count}) in early messages"
                ))
        
        return flags
    
    def _compute_risk_score(self, flags: list) -> float:
        """Aggregate risk score"""
        if not flags:
            return 0.0
        
        max_risk = max(SAFETY_RISK_WEIGHTS[f.type] for f in flags)
        
        # Boost risk if multiple flags present
        if len(flags) > 1:
            max_risk = min(1.0, max_risk + 0.1 * (len(flags) - 1))
        
        return round(max_risk, 2)
    
    def _categorize_risk(self, score: float) -> RiskCategory:
        """Map score to category"""
        if score < 0.3:
            return RiskCategory.SAFE
        elif score < 0.6:
            return RiskCategory.CAUTION
        elif score < 0.85:
            return RiskCategory.DANGER
        else:
            return RiskCategory.ABORT_IMMEDIATELY
    
    def _should_abort_immediately(self, flags: list) -> bool:
        """Check for abort triggers"""
        return any(f.type in ABORT_TRIGGERS and f.severity == "HIGH" for f in flags)
    
    def _compute_confidence(self, flags: list, messages: list) -> float:
        """Confidence in assessment"""
        base = 0.7 if flags else 0.9
        if len(messages) < 10:
            base -= 0.3
        return max(0.3, min(1.0, base))
    
    def _generate_actions(self, flags: list, category: RiskCategory) -> list:
        """Generate recommended actions"""
        actions = []
        
        if category == RiskCategory.ABORT_IMMEDIATELY:
            actions.append("🛑 BLOCK IMMEDIATELY - Do not respond")
            actions.append("Report this profile to the platform")
            actions.append("Screenshot the conversation for your records")
            
        elif category == RiskCategory.DANGER:
            actions.append("⚠️ STOP communication - serious red flags detected")
            actions.append("Do not share personal information")
            actions.append("NEVER send money under any circumstances")
            actions.append("Do not meet in private locations")
            
        elif category == RiskCategory.CAUTION:
            actions.append("⚠️ Proceed with extreme caution")
            actions.append("Meet only in public places")
            actions.append("Tell a friend your plans")
            actions.append("Trust your instincts")
            
        else:
            actions.append("✅ No immediate safety concerns detected")
            actions.append("Continue standard dating safety practices")
        
        # Add specific actions based on flag types
        flag_types = [f.type for f in flags]
        
        if SafetyFlagType.MONEY_REQUEST in flag_types:
            actions.append("⚠️ Money requests from dating matches are almost always scams")
            
        if SafetyFlagType.EARLY_PRIVATE_MEETING in flag_types:
            actions.append("⚠️ Insist on meeting in public first - this is non-negotiable")
        
        return actions
    
    def _generate_explanation(self, flags: list, score: float) -> dict:
        """Human-readable explanation"""
        if not flags:
            return {
                "summary": "No safety concerns detected",
                "details": "Continue using standard dating safety practices"
            }
        
        primary = max(flags, key=lambda f: SAFETY_RISK_WEIGHTS[f.type])
        
        concern_map = {
            SafetyFlagType.MONEY_REQUEST: "Financial scam detected",
            SafetyFlagType.EARLY_PRIVATE_MEETING: "Unsafe meetup pressure",
            SafetyFlagType.LOVE_BOMBING: "Manipulation through excessive intensity",
        }
        
        return {
            "summary": f"Risk Score: {score:.2f}",
            "primary_concern": concern_map.get(primary.type, primary.type.value),
            "details": primary.evidence,
            "flag_count": len(flags)
        }
