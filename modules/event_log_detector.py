from pathlib import Path


def analyze_event_log(event_log_path):
    """
    Analyze a text-based Windows Event Log sample
    for possible log-clearing indicators.
    """

    path = Path(event_log_path)

    if not path.exists():
        return {
            "status": "ERROR",
            "message": f"Event log file does not exist: {path}"
        }

    content = path.read_text(
        encoding="utf-8",
        errors="ignore"
    )

    findings = []

    # Event ID 1102:
    # Security audit log was cleared
    if "1102" in content:
        findings.append(
            "Event ID 1102 detected: Security audit log may have been cleared."
        )

    # Event ID 104:
    # System event log was cleared
    if "104" in content:
        findings.append(
            "Event ID 104 detected: Event log may have been cleared."
        )

    if findings:
        risk_level = "HIGH"
    else:
        risk_level = "LOW"

    return {
        "status": "SUCCESS",
        "file": str(path),
        "risk_level": risk_level,
        "findings": findings
    }