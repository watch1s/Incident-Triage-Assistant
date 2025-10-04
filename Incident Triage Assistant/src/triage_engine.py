from .log_parser import parse_log_file, extract_fields
from .ioc_matcher import load_iocs, match_iocs
from .risk_scorer import calculate_risk_score
from typing import List, Dict

def triage_log_file(log_file: str, ioc_file: str) -> List[Dict]:
    logs = parse_log_file(log_file)
    iocs = load_iocs(ioc_file)
    results = []

    for log in logs:
        fields = extract_fields(log)
        matches = match_iocs(fields, iocs)
        risk = calculate_risk_score(fields, matches)

        # Decision: ignore / investigate / escalate
        if risk >= 50:
            recommendation = "escalate"
        elif risk >= 20:
            recommendation = "investigate"
        else:
            recommendation = "ignore"

        results.append({
            "original_log": log,
            "risk_score": risk,
            "ioc_matches": matches,
            "recommendation": recommendation
        })

    return results