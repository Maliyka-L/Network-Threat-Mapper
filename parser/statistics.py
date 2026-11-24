"""
Traffic statistics functions.
"""


def get_protocol_statistics(connections):

    protocol_counts = {}

    for connection in connections:

        protocol = connection["protocol"]

        if protocol not in protocol_counts:
            protocol_counts[protocol] = 0

        protocol_counts[protocol] += connection["packets"]

    return protocol_counts