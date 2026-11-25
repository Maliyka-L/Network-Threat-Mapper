"""
Detect unusual port usage.
"""

SUSPICIOUS_PORTS = {
    4444,
    5555,
    1337,
    31337
}


def detect_unusual_ports(connections):

    alerts = []

    for connection in connections:

        port = connection["port"]

        if port in SUSPICIOUS_PORTS:

            alerts.append({
                "severity": "LOW",
                "type": "Unusual Port",
                "source": connection["src"],
                "destination": connection["dst"],
                "port": port
            })

    return alerts