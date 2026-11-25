"""
Risk scoring functions.
"""


def calculate_risk_score(alerts):

    score = 0

    for alert in alerts:

        severity = alert["severity"]

        if severity == "HIGH":
            score += 20

        elif severity == "MEDIUM":
            score += 10

        elif severity == "LOW":
            score += 5

    if score > 100:
        score = 100

    return score