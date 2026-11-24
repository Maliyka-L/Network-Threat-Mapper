"""
Replaces real IP addresses with consistent labels for safe sharing.
"""

import ipaddress


# Addresses that don't identify a network, so are left as they are
UNCHANGED = ("255.255.255.255", "0.0.0.0", "::")


# Check if an address is on the local network
def is_internal(address):

    ip = ipaddress.ip_address(address)

    return ip.is_private or ip.is_link_local or ip.is_loopback


# Check if an address should be left as it is
def is_unchanged(address):

    if address in UNCHANGED:
        return True

    return ipaddress.ip_address(address).is_multicast


class Anonymiser:

    def __init__(self):

        # Store each real address and its label
        self.mapping = {}

        # Count labels given out so far
        self.counts = {"HOST": 0, "EXT": 0}

    # Get the label for an IP address
    def ip(self, address):

        # Broadcast and multicast addresses are kept
        try:
            if is_unchanged(address):
                return address
            internal = is_internal(address)
        except ValueError:
            return "UNKNOWN"

        # Give each new address the next label
        if address not in self.mapping:
            prefix = "HOST" if internal else "EXT"
            self.counts[prefix] += 1
            self.mapping[address] = f"{prefix}-{self.counts[prefix]}"

        return self.mapping[address]

    # Anonymise the addresses in a connection
    def connection(self, connection):

        safe = dict(connection)
        safe["src"] = self.ip(connection["src"])
        safe["dst"] = self.ip(connection["dst"])

        return safe
