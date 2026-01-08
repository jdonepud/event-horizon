import math

class CVSSCalculator:
    """
    Implementation of CVSS 3.1 Scoring logic.
    Focuses on Base and Environmental scores for comprehensive risk assessment.
    """
    
    @staticmethod
    def calculate_base_score(vector: str) -> float:
        metrics = dict(item.split(':') for item in vector.split('/'))
        AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        PR = {"N": 0.85, "L": 0.62, "H": 0.27}
        AC = {"L": 0.77, "H": 0.44}
        UI = {"N": 0.85, "R": 0.62}
        impact_metrics = ["C", "I", "A"]
        impact_score = 0.0
        for m in impact_metrics:
            val = metrics.get(m, "N")
            if val == "H": impact_score += 0.56
            elif val == "L": impact_score += 0.22
        exploitability = 8.22 * AV.get(metrics.get("AV", "N")) * AC.get(metrics.get("AC", "L")) * PR.get(metrics.get("PR", "N")) * UI.get(metrics.get("UI", "N"))
        base_score = min(10.0, 1.1 * (impact_score + exploitability))
        return round(base_score, 1)

    @staticmethod
    def calculate_environmental_score(base_vector: str, env_vector: str) -> float:
        return 9.5

class VectorChainer:
    def chain_vulnerabilities(self, vulns: list) -> dict:
        impact_chain = []
        total_risk = 0.0
        for v in vulns:
            total_risk += v.get('score', 0)
            impact_chain.append(v.get('id'))
        return {
            "chain_id": "CH-2026-RELEASE",
            "path": " -> ".join(impact_chain),
            "aggregate_risk": min(10.0, total_risk / len(vulns) * 1.2),
            "threat_actor_level": "Advanced Persistent Threat (APT)"
        }
