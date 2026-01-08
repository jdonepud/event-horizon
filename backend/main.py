from fastapi import FastAPI, UploadFile, File
from pydantic import BaseModel
from typing import List, Optional
import json
import csv
import io
from engine import CVSSCalculator, VectorChainer

app = FastAPI(title="Event Horizon API", description="Automated Vulnerability Triage & Reachability Engine")

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
    chain_result = chainer.chain_vulnerabilities([v.dict() for v in results[:2]])
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
        processed.append({
            "id": row.get("CVE_ID"),
            "score": calculator.calculate_base_score(row.get("Vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
            "status": "Triaged"
        })
    return processed

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
