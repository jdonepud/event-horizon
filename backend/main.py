from fastapi import FastAPI, UploadFile, File
from pydantic import BaseModel
from typing import List, Optional
import json
import csv
import io
try:
    from engine import CVSSCalculator, VectorChainer
except ImportError:
    from .engine import CVSSCalculator, VectorChainer

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Event Horizon API", description="Automated Vulnerability Triage & Reachability Engine")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

calculator = CVSSCalculator()
chainer = VectorChainer()

class Vulnerability(BaseModel):
    id: str
    title: str
    vector: str
    score: Optional[float] = None
    mitre_technique: Optional[str] = None

@app.get("/")
async def root():
    return {"message": "Event Horizon Engine Active", "version": "1.0.0"}

@app.post("/triage")
async def triage_vulnerabilities(vulns: List[Vulnerability]):
    results = []
    for v in vulns:
        v.score = calculator.calculate_base_score(v.vector)
        results.append(v)
    
    # Analyze chaining for the top 2 vulns
    chain_result = chainer.chain_vulnerabilities([v.model_dump() for v in results[:2]])
    
    return {
        "individual_reports": results,
        "attack_path_analysis": chain_result
    }

@app.post("/ingest/csv")
async def ingest_csv(file: UploadFile = File(...)):
    content = await file.read()
    decoded = content.decode('utf-8')
    reader = csv.DictReader(io.StringIO(decoded))
    
    processed = []
    for row in reader:
        cve_id = row.get("CVE_ID", "UNKNOWN")
        vector = row.get("Vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        score = calculator.calculate_base_score(vector)
        processed.append({
            "id": cve_id,
            "title": row.get("Title", "Untitled Vulnerability"),
            "score": score,
            "reachability": row.get("Reachability", "Unknown"),
            "status": "Triaged"
        })
    
    # Perform chaining analysis on the top vulnerabilities found
    chain_result = None
    if len(processed) >= 2:
        # Sort by score for better analysis
        critical_subset = sorted(processed, key=lambda x: x['score'], reverse=True)[:3]
        chain_result = chainer.chain_vulnerabilities(critical_subset)
    
    return {
        "individual_reports": processed,
        "attack_path_analysis": chain_result,
        "summary": {
            "total_processed": len(processed),
            "is_critical": any(p['score'] > 8.0 for p in processed) if processed else False
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
