"""
Detect possible brute force activity.
"""

SENSITIVE_PORTS = {
    21: "FTP",
    22: "SSH",
    3389: "RDP"
}


def detect_brute_force(connections):

    alerts = []

    for connection in connections:

        port = connection["port"]

        if port not in SENSITIVE_PORTS:
            continue

        # Large packet counts may indicate repeated attempts
        if connection["packets"] >= 50:

            alerts.append({
                "severity": "HIGH",
                "type": "Brute Force",
                "protocol": SENSITIVE_PORTS[port],
                "source": connection["src"],
                "destination": connection["dst"],
                "port": port,
                "attempts": connection["packets"]
            })

    return alerts