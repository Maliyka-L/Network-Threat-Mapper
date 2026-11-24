from scapy.all import Ether, IP, TCP, UDP, ICMP

from parser.connection_extractor import extract_connections


# Packets are grouped into connections
def test_grouping():
    packets = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=22),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=22),
        Ether() / IP(src="10.0.0.1", dst="8.8.8.8") / UDP(dport=53),
        Ether() / IP(src="10.0.0.3", dst="10.0.0.1") / ICMP()
    ]

    connections = extract_connections(packets)

    assert len(connections) == 3
    assert connections[0]["port"] == 22
    assert connections[0]["packets"] == 2
    assert connections[0]["protocol"] == "TCP"


# Packets without an IP layer are skipped
def test_non_ip_skipped():
    assert extract_connections([Ether()]) == []
