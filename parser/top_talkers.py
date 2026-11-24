"""
Top talker analysis.
"""


def get_top_talkers(connections):

    host_activity = {}

    for connection in connections:

        source = connection["src"]

        if source not in host_activity:
            host_activity[source] = 0

        host_activity[source] += connection["packets"]

    return sorted(
        host_activity.items(),
        key=lambda item: item[1],
        reverse=True
    )