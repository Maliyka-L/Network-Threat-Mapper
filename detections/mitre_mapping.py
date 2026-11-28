"""
MITRE ATT&CK mappings for detections.
"""

MITRE_MAPPINGS = {
    "Port Scan": {
        "technique": "T1046",
        "name": "Network Service Discovery"
    },
    "Brute Force": {
        "technique": "T1110",
        "name": "Brute Force"
    },
    "Cleartext Protocol": {
        "technique": "T1040",
        "name": "Network Sniffing"
    },
    "Unusual Port": {
        "technique": "T1571",
        "name": "Non-Standard Port"
    }
}


def add_mitre_mappings(alerts):

    enriched_alerts = []

    for alert in alerts:

        mapped_alert = dict(alert)

        alert_type = alert["type"]

        if alert_type in MITRE_MAPPINGS:

            mapped_alert["mitre_id"] = (
                MITRE_MAPPINGS[alert_type]["technique"]
            )

            mapped_alert["mitre_name"] = (
                MITRE_MAPPINGS[alert_type]["name"]
            )

        enriched_alerts.append(mapped_alert)

    return enriched_alerts