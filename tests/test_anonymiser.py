from utils.anonymiser import Anonymiser


# Same address always gets the same label
def test_consistent_labels():
    anonymiser = Anonymiser()
    assert anonymiser.ip("192.168.1.10") == "HOST-1"
    assert anonymiser.ip("192.168.1.10") == "HOST-1"


# Internal and external addresses are numbered separately
def test_internal_and_external():
    anonymiser = Anonymiser()
    assert anonymiser.ip("192.168.1.10") == "HOST-1"
    assert anonymiser.ip("8.8.8.8") == "EXT-1"
    assert anonymiser.ip("10.0.0.5") == "HOST-2"
    assert anonymiser.ip("142.250.180.14") == "EXT-2"


# IPv6 addresses are anonymised too
def test_ipv6():
    anonymiser = Anonymiser()
    assert anonymiser.ip("fe80::1") == "HOST-1"
    assert anonymiser.ip("2001:4860:4860::8888") == "EXT-1"


# Broadcast and multicast addresses are kept
def test_unchanged_addresses():
    anonymiser = Anonymiser()
    assert anonymiser.ip("255.255.255.255") == "255.255.255.255"
    assert anonymiser.ip("224.0.0.251") == "224.0.0.251"
    assert anonymiser.ip("ff02::fb") == "ff02::fb"


# Invalid addresses don't crash
def test_invalid_address():
    assert Anonymiser().ip("not-an-ip") == "UNKNOWN"


# Connections keep their other details
def test_connection():
    anonymiser = Anonymiser()
    original = {"src": "192.168.1.10", "dst": "8.8.8.8", "protocol": "UDP",
                "port": 53, "packets": 4, "bytes": 300}
    safe = anonymiser.connection(original)

    assert safe["src"] == "HOST-1"
    assert safe["dst"] == "EXT-1"
    assert safe["port"] == 53
    assert original["src"] == "192.168.1.10"
