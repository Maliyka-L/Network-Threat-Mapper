"""
Network Threat Mapper.

Entry point for the application.
"""

import sys

from parser.pcap_loader import load_pcap


def main():

    # Check the user supplied a PCAP file
    if len(sys.argv) < 2:
        print("Usage: python main.py <pcap_file>")
        return

    # Get the file path from the command line
    file_path = sys.argv[1]

    # Load packets from the capture
    packets = load_pcap(file_path)

    # Display how many packets were found
    print(f"Loaded {len(packets)} packets")


if __name__ == "__main__":
    main()