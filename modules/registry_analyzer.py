import os

def analyze_registry():

    findings = []
    risk = "LOW"

    registry_paths = [
        r"C:\Windows\System32\config\SAM",
        r"C:\Windows\System32\config\SYSTEM",
        r"C:\Windows\System32\config\SOFTWARE",
        r"C:\Windows\System32\config\SECURITY"
    ]

    for path in registry_paths:
        if os.path.exists(path):
            findings.append(f"Registry hive found: {path}")
        else:
            findings.append(f"Registry hive missing: {path}")
            risk = "MEDIUM"

    return {
        "risk_level": risk,
        "findings": findings
    }