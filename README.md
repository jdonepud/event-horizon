# Event Horizon

Automated Vulnerability Triage & Reachability Engine

Event Horizon is a high-performance security tool designed to automate vulnerability ingestion, scoring, and contextual risk analysis. It bridges the gap between raw vulnerability reports and actionable security intelligence by implementing CVSS 3.1 standards and advanced vector chaining analysis.

## Key Features

- Automated CVSS 3.1 Scoring
  - Precision calculation of Base and Environmental scores
  - Fully aligned with FIRST.org CVSS 3.1 specification

- Vector Chaining & Reachability Analysis
  - Identifies complex attack paths where multiple vulnerabilities combine
  - Surfaces compounded, real-world exploitability risk

- High-Fidelity Dashboard
  - Real-time, glassmorphic visualization layer
  - Live monitoring of ingestion and scoring pipelines

- RESTful API
  - Built with FastAPI for speed and scalability
  - Simple integration with external security platforms

## Project Structure

event-horizon/
backend/              Core logic and API implementation
frontend/             Real-time dashboard interface
automate_triage.py    CLI tool for rapid processing
sample_vulns.csv      Example dataset
requirements.txt
README.md

## Getting Started

Prerequisites:
- Python 3.8+
- FastAPI
- Uvicorn

Installation:
1. Clone the repository:
git clone https://github.com/jdonepud/event-horizon.git
cd event-horizon

2. Install dependencies:
pip install -r requirements.txt

3. Run the API:
python backend/main.py

## Usage

- Ingest vulnerability data via API or CSV
- Automatically compute CVSS scores
- Analyze attack paths using vector chaining
- Visualize risk in real time via the dashboard

## Roadmap

- CVSS v4 support
- Exploit intelligence integration (EPSS, KEV)
- Graph-based attack path analysis
- Role-based access control
- Containerized deployment

## License

MIT License
