from typing import List, Dict
def calculate_risk_score(log_fields: Dict, ioc_matches: List[str]) -> int:
    score = 0
    if ioc_matches:
        score += 50  
    if "exploit" in log_fields.get("signature", "").lower():
        score += 30
    if log_fields.get("event_type") == "ALERT":
        score += 20
    return min(score, 100)  # Return its smallest amoung "score" and "100"