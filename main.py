"""
Network Threat Mapper.

Entry point for the application.
"""

import argparse
from parser.statistics import get_protocol_statistics
from parser.pcap_loader import load_pcap
from parser.connection_extractor import extract_connections
from utils.anonymiser import Anonymiser
from parser.host_classifier import classify_host
from parser.top_talkers import get_top_talkers


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

    print(f"{'Source':<28} {'Destination':<28} {'Protocol':<9} {'Port':<7} {'Packets':>8} {'Bytes':>10}")
    print("-" * 95)

    for c in connections:
        port = c["port"] if c["port"] is not None else "-"
        print(f"{c['src']:<28} {c['dst']:<28} {c['protocol']:<9} {str(port):<7} {c['packets']:>8} {c['bytes']:>10}")


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

    print("\nProtocol Statistics")
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

    top_connections = connections[:args.top]
    top_connections = connections[:args.top]

    # Hide real IP addresses if asked
    if args.anonymise:
        anonymiser = Anonymiser()
        top_connections = [
            anonymiser.connection(c)
            for c in top_connections
        ]

if __name__ == "__main__":
    main()
