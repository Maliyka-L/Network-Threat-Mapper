"""
Loads packet capture files.
"""

from scapy.all import rdpcap


def load_pcap(file_path):
    # Read all packets from the capture file
    packets = rdpcap(file_path)

    return packets