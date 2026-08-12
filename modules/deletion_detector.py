from pathlib import Path

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1",
    ".vbs", ".dll", ".scr",
    ".tmp", ".bak", ".enc", ".crypt"
}


def analyze_folder(folder_path):

    result = {
        "risk_level": "LOW",
        "findings": [],
        "total_files": 0,
        "hidden_files": 0,
        "empty_files": 0,
        "large_files": 0,
        "suspicious_files": []
    }

    folder = Path(folder_path)

    if folder.is_file():
        folder = folder.parent

    if not folder.exists():

        result["risk_level"] = "HIGH"

        result["findings"].append(
            "Folder not found."
        )

        return result

    names = set()

    for file in folder.rglob("*"):

        if not file.is_file():
            continue

        result["total_files"] += 1

        try:

            size = file.stat().st_size

            # Empty file
            if size == 0:
                result["empty_files"] += 1

            # Large file (>100 MB)
            if size > 100 * 1024 * 1024:
                result["large_files"] += 1

            # Hidden file
            if file.name.startswith("."):
                result["hidden_files"] += 1

            # Duplicate filename
            if file.name in names:
                result["findings"].append(
                    f"Duplicate filename: {file.name}"
                )
            else:
                names.add(file.name)

            # Suspicious extension
            if file.suffix.lower() in SUSPICIOUS_EXTENSIONS:

                result["suspicious_files"].append(
                    file.name
                )

        except Exception:
            pass

    if result["hidden_files"]:

        result["findings"].append(
            f"{result['hidden_files']} hidden file(s) detected."
        )

    if result["empty_files"]:

        result["findings"].append(
            f"{result['empty_files']} empty file(s) detected."
        )

    if result["large_files"]:

        result["findings"].append(
            f"{result['large_files']} unusually large file(s) detected."
        )

    if result["suspicious_files"]:

        result["findings"].append(
            f"{len(result['suspicious_files'])} suspicious file(s) detected."
        )

    if result["suspicious_files"]:

        result["risk_level"] = "HIGH"

    elif result["hidden_files"] or result["empty_files"]:

        result["risk_level"] = "MEDIUM"

    return result