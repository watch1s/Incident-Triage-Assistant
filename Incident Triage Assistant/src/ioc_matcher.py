from typing import List, Dict

def load_iocs(file_path: str) -> set:
    with open(file_path, 'r') as f:
        return set(line.strip() for line in f if line.strip())

def match_iocs(log_fields: Dict, ioc_set: set) -> List[str]:
    matches = []
    for field in ["src_ip", "dst_ip", "payload"]:
        value = str(log_fields.get(field, ""))
        if value in ioc_set:
            matches.append(f"{field}: {value}")
    return matches