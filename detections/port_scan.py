"""
Detect potential port scanning activity.
"""


def detect_port_scans(connections):

    alerts = []

    source_ports = {}

    for connection in connections:

        source = connection["src"]
        port = connection["port"]

        if port is None:
            continue

        if source not in source_ports:
            source_ports[source] = set()

        source_ports[source].add(port)

    for source, ports in source_ports.items():

        # Alert if a host touches many ports
        if len(ports) >= 10:

            alerts.append({
                "severity": "HIGH",
                "type": "Port Scan",
                "source": source,
                "ports": len(ports)
            })

    return alerts