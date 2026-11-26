"""
Detect potential port scanning activity.
"""


def detect_port_scans(connections):

    alerts = []

    scan_tracker = {}

    for connection in connections:

        source = connection["src"]
        destination = connection["dst"]
        port = connection["port"]

        if port is None:
            continue

        key = (source, destination)

        if key not in scan_tracker:
            scan_tracker[key] = set()

        scan_tracker[key].add(port)

    for (source, destination), ports in scan_tracker.items():

        if len(ports) >= 10:

            alerts.append({
                "severity": "HIGH",
                "type": "Port Scan",
                "source": source,
                "destination": destination,
                "ports": len(ports)
            })

    return alerts