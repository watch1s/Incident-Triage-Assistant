from fastapi import FastAPI, HTTPException
from .triage_engine import triage_log_file
from pydantic import BaseModel
from typing import List
import tempfile
import os
import json

class LogEntry(BaseModel):
    timestamp: str
    src_ip: str
    dst_ip: str
    event_type: str
    signature: str = ""
    payload: str = ""

class LogBatch(BaseModel):
    logs: List[LogEntry]
    class Config:
        schema_extra = {
            "example": {
                "logs": [
                    {
                        "timestamp": "2024-06-01T10:00:00Z",
                        "src_ip": "192.168.1.10",
                        "dst_ip": "192.168.100.50",
                        "event_type": "ALERT",
                        "signature": "ET EXPLOIT...",
                        "payload": "GET /malicious.php"
                    }
                ]
            }
        }

app = FastAPI(
    title="Incident Triage Assistant",
    description="""
    Automated triage service for SOC teams.
    - Matches logs against local IOCs
    - Assigns risk scores
    - Recommends actions: ignore / investigate / escalate
    """,
    version="alpha 1.0"
)

@app.get("/health")
async def health_check():
    """Returns 200 if service is ready."""
    ioc_path = "rules/iocs.txt"
    if os.path.exists(ioc_path):
        return {"status": "healthy", "ioc_file": ioc_path}
    else:
        raise HTTPException(status_code=500, detail="IOC file missing")

@app.post("/triage", summary="Triage security logs", tags=["Triage"])
def triage_endpoint(data: LogBatch):
    try:
        logs_to_dict = [log.dict() for log in data.logs]

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp_file:
            json.dump(logs_to_dict, tmp_file)
            tmp_file_path = tmp_file.name

        ioc_file_path = "rules/iocs.txt"
        if not os.path.exists(ioc_file_path):
            raise HTTPException(status_code=500, detail="IOC file not found")

        results = triage_log_file(tmp_file_path, ioc_file_path)
        os.unlink(tmp_file_path)

        return {"results": results}
        
    except Exception as e:
        if 'tmp_file_path' in locals():
            if os.path.exists(tmp_file_path):
                os.unlink(tmp_file_path)
        raise HTTPException(status_code=500, detail=f"Triage failed{str(e)}")

@app.post("/v1/triage", summary="Triage security logs", tags=["Triage"])
def triage_endpoint_v1(data: LogBatch):
    try:
        logs_to_dict = [log.dict() for log in data.logs]

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tmp_file:
            json.dump(logs_to_dict, tmp_file)
            tmp_file_path = tmp_file.name

        ioc_file_path = "rules/iocs.txt"
        if not os.path.exists(ioc_file_path):
            raise HTTPException(
                                 status_code=500,
                                 detail={
                                 "error": "TriageFailed",
                                 "message": str(e),
                                 "suggestion": "Check log format and IOC file"})

        results = triage_log_file(tmp_file_path, ioc_file_path)
        os.unlink(tmp_file_path)

        return {"results": results}
        
    except Exception as e:
        if 'tmp_file_path' in locals():
            if os.path.exists(tmp_file_path):
                os.unlink(tmp_file_path)
        raise HTTPException(status_code=500, detail=f"Triage failed{str(e)}")
