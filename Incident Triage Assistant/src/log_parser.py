import json
from typing import List, Dict

def parse_log_file(file_path: str) -> List[Dict]:
    """Reads log files(only JSON)"""
    with open(file_path, 'r') as f:
        logs = json.load(f)
    return logs

def extract_fields(log: Dict) -> Dict:
    """Extract speicfy fields from log (etc: src_ip, dst_ip, event_type)."""
    return {
        "src_ip": log.get("src_ip"),
        "dst_ip": log.get("dst_ip"),
        "event_type": log.get("event_type"),
        "timestamp": log.get("timestamp"),
        "signature": log.get("signature", ""),
        "payload": log.get("payload", "")
    }