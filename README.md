# Incident Triage Assistant

> 🛡️ **Automated SOC Triage Tool** that reduces manual investigation time by filtering false positives and prioritizing real threats.

This tool parses security logs, matches them against known Indicators of Compromise (IOCs), calculates a risk score, and recommends an action:  
 **ignore** |  **investigate**! |  **escalate**!!

Built with Python, FastAPI, and rule-based logic — ready for CLI, **CURRENTLY NOT READY FOR** SIEM/SOAR integration.

---

##  Features

- **CLI Interface**: Process log files in batch mode
- **REST API**: `/v1/triage` endpoint for real-time integration
- **IOC Matching**: Supports IPs, domains, hashes (via `rules/iocs.txt`)
- **Risk Scoring**: Rule-based engine (exploit keywords, event type, IOC hits)
- **Swagger UI**: Architecture documentation at `/docs`
- **Lightweight**: No external dependencies (works offline)

---

##  Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/watch1s/incident-triage-assistant.git
cd incident-triage-assistant
