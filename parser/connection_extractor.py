"""
Groups packets into connections.
"""

from scapy.all import IP, IPv6, TCP, UDP, ICMP


# Build a list of connections from packets
def extract_connections(packets):

    # Store connections by source, destination, protocol and port
    connections = {}

    for packet in packets:

        # Get the IP layer, skipping packets without one
        if packet.haslayer(IP):
            layer = packet[IP]
        elif packet.haslayer(IPv6):
            layer = packet[IPv6]
        else:
            continue

        # Work out the protocol and destination port
        if packet.haslayer(TCP):
            protocol = "TCP"
            port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            port = None
        else:
            protocol = "OTHER"
            port = None

        key = (layer.src, layer.dst, protocol, port)

        # Add a new connection the first time it's seen
        if key not in connections:
            connections[key] = {
                "src": layer.src,
                "dst": layer.dst,
                "protocol": protocol,
                "port": port,
                "packets": 0,
                "bytes": 0
            }

        # Count packets and bytes
        connections[key]["packets"] += 1
        connections[key]["bytes"] += len(packet)

    # Busiest connections first
    return sorted(
        connections.values(),
        key=lambda c: c["packets"],
        reverse=True
    )
