import os
from datetime import datetime


def analyze_timestamps(file_path):

    try:
        if not os.path.exists(file_path):
            return {
                "status": "ERROR",
                "risk_level": "HIGH",
                "findings": [f"File not found: {file_path}"]
            }

        created_time = os.path.getctime(file_path)
        modified_time = os.path.getmtime(file_path)
        accessed_time = os.path.getatime(file_path)

        created = datetime.fromtimestamp(
            created_time
        ).strftime("%Y-%m-%d %H:%M:%S")

        modified = datetime.fromtimestamp(
            modified_time
        ).strftime("%Y-%m-%d %H:%M:%S")

        accessed = datetime.fromtimestamp(
            accessed_time
        ).strftime("%Y-%m-%d %H:%M:%S")

        findings = []

        if modified_time < created_time:
            findings.append(
                "Modified time is earlier than creation time."
            )

        if accessed_time < created_time:
            findings.append(
                "Accessed time is earlier than creation time."
            )

        return {
            "status": "SUCCESS",
            "file_path": file_path,
            "created": created,
            "modified": modified,
            "accessed": accessed,
            "risk_level": "LOW" if not findings else "MEDIUM",
            "findings": findings
        }

    except Exception as e:

        return {
            "status": "ERROR",
            "risk_level": "HIGH",
            "findings": [str(e)]
        }