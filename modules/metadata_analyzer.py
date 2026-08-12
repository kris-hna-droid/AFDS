from pathlib import Path
from datetime import datetime
import os
import stat


def analyze_metadata(file_path):
    """
    Analyze file metadata for AFDS.
    """

    path = Path(file_path)

    result = {
        "file_name": "",
        "file_extension": "",
        "file_path": "",
        "file_size": 0,
        "created": "",
        "modified": "",
        "accessed": "",
        "read_only": False,
        "hidden": False,
        "risk_level": "LOW",
        "findings": []
    }

    if not path.exists():

        result["risk_level"] = "HIGH"
        result["findings"].append("File not found.")

        return result

    try:

        stats = path.stat()

        result["file_name"] = path.name
        result["file_extension"] = path.suffix
        result["file_path"] = str(path.resolve())
        result["file_size"] = stats.st_size

        result["created"] = datetime.fromtimestamp(
            stats.st_ctime
        ).strftime("%Y-%m-%d %H:%M:%S")

        result["modified"] = datetime.fromtimestamp(
            stats.st_mtime
        ).strftime("%Y-%m-%d %H:%M:%S")

        result["accessed"] = datetime.fromtimestamp(
            stats.st_atime
        ).strftime("%Y-%m-%d %H:%M:%S")

        # Read-only detection
        result["read_only"] = not os.access(
            file_path,
            os.W_OK
        )

        # Hidden file detection
        if path.name.startswith("."):
            result["hidden"] = True

        if os.name == "nt":
            try:
                attributes = os.stat(file_path).st_file_attributes

                if attributes & stat.FILE_ATTRIBUTE_HIDDEN:
                    result["hidden"] = True

            except Exception:
                pass

        # Suspicious extension
        suspicious_extensions = [
            ".tmp",
            ".bak",
            ".enc",
            ".crypt",
            ".lock"
        ]

        if path.suffix.lower() in suspicious_extensions:

            result["risk_level"] = "MEDIUM"

            result["findings"].append(
                f"Suspicious extension detected ({path.suffix})"
            )

        # Empty file
        if result["file_size"] == 0:

            result["risk_level"] = "MEDIUM"

            result["findings"].append(
                "Empty file detected."
            )

        # Hidden file
        if result["hidden"]:

            result["risk_level"] = "MEDIUM"

            result["findings"].append(
                "Hidden file detected."
            )

        # Read-only
        if result["read_only"]:

            result["findings"].append(
                "File is read-only."
            )

        if len(result["findings"]) == 0:

            result["findings"].append(
                "No suspicious metadata detected."
            )

    except Exception as e:

        result["risk_level"] = "HIGH"

        result["findings"].append(str(e))

    return result