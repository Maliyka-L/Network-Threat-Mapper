"""
Host classification functions.
"""

import ipaddress


def classify_host(ip_address):

    try:
        ip = ipaddress.ip_address(ip_address)

        if ip.is_private:
            return "INTERNAL"

        return "EXTERNAL"

    except ValueError:
        return "UNKNOWN"