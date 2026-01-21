import json
import csv
try:
    from engine import CVSSCalculator, VectorChainer
except ImportError:
    from backend.engine import CVSSCalculator, VectorChainer

def run_automation_audit(csv_path):
    print(f"🚀 Initializing Automated Audit: {csv_path}")
    calculator = CVSSCalculator()
    chainer = VectorChainer()
    
    reports = []
    with open(csv_path, mode='r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            score = calculator.calculate_base_score(row['Vector'])
            reports.append({
                "id": row['CVE_ID'],
                "impact": row['Title'],
                "score": score,
                "reachability": row['Reachability']
            })
            print(f"✅ Triaged {row['CVE_ID']} | Score: {score}")

    # Analyze critical chains
    critical_vulns = [v for v in reports if v['score'] > 8.0]
    if len(critical_vulns) >= 2:
        chain = chainer.chain_vulnerabilities(critical_vulns)
        print("\n⚠️  CRITICAL ATTACK PATH DETECTED")
        print(f"Path: {chain['path']}")
        print(f"Aggregate Risk: {chain['aggregate_risk']}")

if __name__ == "__main__":
    import sys
    # Default to original sample if no argument is provided
    target_file = sys.argv[1] if len(sys.argv) > 1 else "sample_vulns.csv"
    run_automation_audit(target_file)

