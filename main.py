"""
Network Threat Mapper.

Entry point for the application.
"""

import argparse
from parser.statistics import get_protocol_statistics
from parser.pcap_loader import load_pcap
from parser.connection_extractor import extract_connections
from utils.anonymiser import Anonymiser


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

    top_connections = connections[:args.top]

    # Hide real IP addresses if asked
    if args.anonymise:
        anonymiser = Anonymiser()
        top_connections = [
            anonymiser.connection(c)
            for c in top_connections
        ]

    # Display the busiest connections
    print_connections(top_connections)



if __name__ == "__main__":
    main()
