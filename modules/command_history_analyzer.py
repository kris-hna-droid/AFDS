from pathlib import Path

SUSPICIOUS_COMMANDS = [
    "del ",
    "erase ",
    "rd ",
    "rmdir ",
    "format ",
    "diskpart",
    "clean",
    "cipher",
    "cipher /w",
    "wevtutil cl",
    "vssadmin delete shadows",
    "fsutil",
    "sdelete",
    "powershell remove-item",
    "clear-eventlog",
    "history -c",
    "rm -rf"
]


def analyze_command_history(file_path):

    result = {
        "risk_level": "LOW",
        "total_commands": 0,
        "suspicious_commands": [],
        "findings": []
    }

    path = Path(file_path)

    if not path.exists():
        result["risk_level"] = "HIGH"
        result["findings"].append("Command history file not found.")
        return result

    try:

        with open(path, "r", encoding="utf-8", errors="ignore") as file:

            for line in file:

                command = line.strip()

                if not command:
                    continue

                result["total_commands"] += 1

                lower_command = command.lower()

                for suspicious in SUSPICIOUS_COMMANDS:

                    if suspicious in lower_command:
                        result["suspicious_commands"].append(command)
                        break

        if result["suspicious_commands"]:

            result["risk_level"] = "HIGH"

            result["findings"].append(
                f"{len(result['suspicious_commands'])} suspicious command(s) detected."
            )

        else:

            result["findings"].append(
                "No suspicious commands detected."
            )

    except Exception as e:

        result["risk_level"] = "HIGH"
        result["findings"].append(str(e))

    return result