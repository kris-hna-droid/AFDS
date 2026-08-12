from pathlib import Path

# Extensions commonly associated with encrypted or protected files
ENCRYPTED_EXTENSIONS = {
    ".enc",
    ".crypt",
    ".aes",
    ".gpg",
    ".pgp",
    ".zip",
    ".7z",
    ".rar"
}


def analyze_encryption(file_path):

    result = {
        "risk_level": "LOW",
        "encrypted": False,
        "encryption_type": "None",
        "findings": []
    }

    path = Path(file_path)

    if not path.exists():

        result["risk_level"] = "HIGH"
        result["findings"].append("File not found.")
        return result

    extension = path.suffix.lower()

    if extension in ENCRYPTED_EXTENSIONS:

        result["encrypted"] = True
        result["encryption_type"] = extension
        result["risk_level"] = "HIGH"

        result["findings"].append(
            f"Encrypted or password-protected file detected ({extension})."
        )

    else:

        result["findings"].append(
            "No encryption detected."
        )

    return result