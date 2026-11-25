"""
Port analysis functions.
"""


def get_top_ports(connections):

    ports = {}

    for connection in connections:

        port = connection["port"]

        if port is None:
            continue

        if port not in ports:
            ports[port] = 0

        ports[port] += 1

    return sorted(
        ports.items(),
        key=lambda item: item[1],
        reverse=True
    )