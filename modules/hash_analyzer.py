import hashlib
import os


def analyze_hash(file_path):
    """
    Calculate SHA-256 hash of a file.
    """

    if not os.path.exists(file_path):
        return {
            "status": "ERROR",
            "message": f"File does not exist: {file_path}"
        }

    try:
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as file:
            for block in iter(lambda: file.read(4096), b""):
                sha256.update(block)

        return {
            "status": "SUCCESS",
            "file": file_path,
            "sha256_hash": sha256.hexdigest()
        }

    except Exception as e:
        return {
            "status": "ERROR",
            "message": str(e)
        }