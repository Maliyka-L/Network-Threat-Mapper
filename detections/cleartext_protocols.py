"""
Detect cleartext protocols.
"""

CLEAR_TEXT_PORTS = {
    21: "FTP",
    23: "Telnet",
    80: "HTTP"
}


def detect_cleartext_protocols(connections):

    alerts = []

    for connection in connections:

        port = connection["port"]

        if port in CLEAR_TEXT_PORTS:

            alerts.append({
                "severity": "MEDIUM",
                "type": "Cleartext Protocol",
                "protocol": CLEAR_TEXT_PORTS[port],
                "port": port
            })

    return alerts