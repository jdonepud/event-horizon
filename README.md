# Event Horizon: Automated Vulnerability Triage & Reachability Engine

Event Horizon is a high-performance security tool designed to automate the ingestion, scoring, and analysis of vulnerabilities. It bridges the gap between raw vulnerability reports and actionable risk intelligence by implementation of CVSS 3.1 standards and advanced vector chaining analysis.

## Key Features

- **Automated CVSS Scoring**: Precision calculation of Base and Environmental scores using the First.org CVSS 3.1 specification.
- **Vector Chaining Analysis**: Identifies complex attack paths where multiple vulnerabilities (e.g., SSRF + Internal SQLi) combine to create high-impact reachability.
- **High-Fidelity Dashboard**: A glassmorphic, real-time visualization layer for monitoring ingestion pipelines and threat heatmaps.
- **RESTful API**: Built with FastAPI for seamless integration into existing CI/CD or SecOps workflows.
- **Reachability Mapping**: Correlates vulnerability data with asset location and accessibility to prioritize remediation strategy.

## Project Structure

- `backend/`: Core logic and API implementation.
  - `engine.py`: CVSS scoring and attack path analysis logic.
  - `main.py`: FastAPI service for data ingestion and triage.
- `frontend/`: Real-time dashboard interface (Vanilla JS/CSS for zero-dependency performance).
- `automate_triage.py`: CLI tool for rapid processing of vulnerability datasets.
- `sample_vulns.csv`: Example dataset for testing and demonstration.

## Getting Started

### Prerequisites

- Python 3.8+
- FastAPI & Uvicorn (for the API)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/[your-username]/event-horizon.git
   cd event-horizon
   ```

2. Install dependencies:
   ```bash
   pip install fastapi uvicorn
   ```

3. Run the API:
   ```bash
   python backend/main.py
   ```

4. Run the Automation Script:
   ```bash
   python automate_triage.py
   ```

## Disclaimer

This tool is designed for security research and vulnerability management. Ensure you have proper authorization before testing against any production systems.
