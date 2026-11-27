"""
Alert summary functions.
"""


def get_alert_summary(alerts):

    summary = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for alert in alerts:

        severity = alert["severity"]

        if severity in summary:
            summary[severity] += 1

    return summary