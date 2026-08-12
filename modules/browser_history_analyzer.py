from pathlib import Path


SUSPICIOUS_KEYWORDS = [
    "tor",
    "dark web",
    "anonymous",
    "incognito",
    "delete history",
    "erase traces",
    "anti forensic",
    "ccleaner",
    "bleachbit"
]


def analyze_browser_history(file_path):

    result = {
        "risk_level": "LOW",
        "visited_sites": 0,
        "suspicious_entries": [],
        "findings": []
    }

    path = Path(file_path)

    if not path.exists():

        result["risk_level"] = "HIGH"
        result["findings"].append("Browser history file not found.")
        return result

    try:

        with open(path, "r", encoding="utf-8", errors="ignore") as file:

            for line in file:

                result["visited_sites"] += 1

                lower_line = line.lower()

                for keyword in SUSPICIOUS_KEYWORDS:

                    if keyword in lower_line:
                        result["suspicious_entries"].append(line.strip())

        if result["suspicious_entries"]:

            result["risk_level"] = "HIGH"

            result["findings"].append(
                f"{len(result['suspicious_entries'])} suspicious browser history entries detected."
            )

        else:

            result["findings"].append(
                "No suspicious browser history detected."
            )

    except Exception as e:

        result["risk_level"] = "HIGH"
        result["findings"].append(str(e))

    return result