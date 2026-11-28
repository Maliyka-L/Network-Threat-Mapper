"""
Network Threat Mapper.

Entry point for the application.
"""

import argparse

from parser.statistics import get_protocol_statistics
from parser.pcap_loader import load_pcap
from parser.connection_extractor import extract_connections
from parser.host_classifier import classify_host
from parser.top_talkers import get_top_talkers
from parser.port_analysis import get_top_ports

from utils.anonymiser import Anonymiser

from detections.unusual_ports import detect_unusual_ports
from detections.cleartext_protocols import detect_cleartext_protocols
from detections.port_scan import detect_port_scans
from detections.risk_score import calculate_risk_score
from detections.brute_force import detect_brute_force
from detections.alert_summary import get_alert_summary
from detections.mitre_mapping import add_mitre_mappings
from reports.json_export import export_json

# Read the command line options
def get_arguments():

    arg_parser = argparse.ArgumentParser(
        description="Analyse a packet capture for network threats."
    )

    arg_parser.add_argument(
        "pcap_file",
        help="Path to a .pcap or .pcapng file"
    )

    arg_parser.add_argument(
        "--anonymise",
        action="store_true",
        help="Replace real IP addresses with labels such as HOST-1"
    )

    arg_parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of connections to show (default 10)"
    )

    return arg_parser.parse_args()


# Display connections as a table
def print_connections(connections):

    print(
        f"{'Source':<28} "
        f"{'Destination':<28} "
        f"{'Protocol':<9} "
        f"{'Port':<7} "
        f"{'Packets':>8} "
        f"{'Bytes':>10}"
    )

    print("-" * 95)

    for connection in connections:

        port = (
            connection["port"]
            if connection["port"] is not None
            else "-"
        )

        print(
            f"{connection['src']:<28} "
            f"{connection['dst']:<28} "
            f"{connection['protocol']:<9} "
            f"{str(port):<7} "
            f"{connection['packets']:>8} "
            f"{connection['bytes']:>10}"
        )


def main():

    args = get_arguments()

    # Load packets from the capture
    packets = load_pcap(args.pcap_file)

    print(f"Loaded {len(packets)} packets")

    # Group packets into connections
    connections = extract_connections(packets)

    print(f"Found {len(connections)} connections\n")

    # Calculate protocol statistics
    protocol_stats = get_protocol_statistics(connections)

    print("Protocol Statistics")
    print("-" * 25)

    for protocol, count in protocol_stats.items():
        print(f"{protocol}: {count:,} packets")

    print()

    # Count internal and external hosts
    internal_hosts = set()
    external_hosts = set()

    for connection in connections:

        if classify_host(connection["src"]) == "INTERNAL":
            internal_hosts.add(connection["src"])
        else:
            external_hosts.add(connection["src"])

        if classify_host(connection["dst"]) == "INTERNAL":
            internal_hosts.add(connection["dst"])
        else:
            external_hosts.add(connection["dst"])

    print("Host Summary")
    print("-" * 25)
    print(f"Internal Hosts: {len(internal_hosts)}")
    print(f"External Hosts: {len(external_hosts)}")
    print()

    # Identify the hosts generating the most traffic
    top_talkers = get_top_talkers(connections)

    if args.anonymise:

        anonymiser = Anonymiser()

        anonymised_talkers = []

        for host, packet_count in top_talkers[:5]:

            anonymised_host = anonymiser.ip(host)

            anonymised_talkers.append(
                (anonymised_host, packet_count)
            )

        top_talkers = anonymised_talkers

    print("Top Talkers")
    print("-" * 25)

    for host, packet_count in top_talkers[:5]:
        print(f"{host}: {packet_count:,} packets")

    print()

    # Analyse most common ports
    top_ports = get_top_ports(connections)

    print("Top Ports")
    print("-" * 25)

    for port, count in top_ports[:5]:
        print(f"{port}: {count} connections")

    print()

    # Run threat detections
    alerts = []

    alerts.extend(
        detect_unusual_ports(connections)
    )

    alerts.extend(
        detect_cleartext_protocols(connections)
    )

    alerts.extend(
        detect_port_scans(connections)
    )

    alerts.extend(
        detect_brute_force(connections)
    )

    alerts = add_mitre_mappings(alerts)

    print("Threat Alerts")
    print("-" * 25)

    if not alerts:

        print("No threats detected")

    else:

        for alert in alerts[:5]:

            mitre = (
            f"{alert['mitre_id']} "
            f"({alert['mitre_name']})"
            )

        if alert["type"] == "Port Scan":

            print(
                f"[{alert['severity']}] "
                f"{alert['type']} "
                f"| MITRE: {mitre} "
                f"| {alert['source']} -> "
                f"{alert['destination']}"
            )

        elif alert["type"] == "Brute Force":

            print(
                f"[{alert['severity']}] "
                f"{alert['protocol']} brute force "
                f"| MITRE: {mitre}"
            )

        elif alert["type"] == "Cleartext Protocol":

            print(
                f"[{alert['severity']}] "
                f"{alert['protocol']} traffic "
                f"| MITRE: {mitre}"
            )

        else:

            print(
                f"[{alert['severity']}] "
                f"{alert['type']} "
                f"| MITRE: {mitre}"
            )

    print()

    print()

    summary = get_alert_summary(alerts)
    print("Alert Summary")
    print("-" * 25)
    print(f"HIGH: {summary['HIGH']}")
    print(f"MEDIUM: {summary['MEDIUM']}")
    print(f"LOW: {summary['LOW']}")
    print()

    report_data = {
        "packet_count": len(packets),
        "connection_count": len(connections),
        "alerts": alerts,
        "alert_summary": summary
    }

    output_file = export_json(report_data)

    print("Export")
    print("-" * 25)
    print(f"JSON report saved: {output_file}")
    print()

    # Calculate risk score
    risk_score = calculate_risk_score(alerts)

    print("Risk Score")
    print("-" * 25)
    print(f"Score: {risk_score}/100")

    if risk_score >= 70:
        print("Risk Level: HIGH")

    elif risk_score >= 30:
        print("Risk Level: MEDIUM")

    else:
        print("Risk Level: LOW")

    print()

    # Select top connections for display
    top_connections = connections[:args.top]

    # Hide real IP addresses if asked
    if args.anonymise:

        anonymiser = Anonymiser()

        top_connections = [
            anonymiser.connection(connection)
            for connection in top_connections
        ]

    # Display connection table
    print_connections(top_connections)


if __name__ == "__main__":
    main()