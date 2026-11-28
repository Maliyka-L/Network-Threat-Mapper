"""
Export analysis findings to JSON.
"""

import json
import os


def export_json(results, output_file="reports/findings.json"):

    os.makedirs("reports", exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as file:

        json.dump(
            results,
            file,
            indent=4
        )

    return output_file