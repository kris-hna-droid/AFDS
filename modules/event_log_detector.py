from pathlib import Path
import re


# ============================================================
# Important Windows Event IDs
# ============================================================

EVENT_DEFINITIONS = {
    "4624": {
        "meaning": "Successful logon",
        "importance": "Shows when and how an account logged in",
        "risk": "LOW"
    },

    "4625": {
        "meaning": "Failed logon",
        "importance": "Repeated failures may indicate password guessing",
        "risk": "MEDIUM"
    },

    "4634": {
        "meaning": "Account logoff",
        "importance": "Helps establish user activity timelines",
        "risk": "LOW"
    },

    "4648": {
        "meaning": "Logon using explicit credentials",
        "importance": "May indicate use of alternate credentials",
        "risk": "MEDIUM"
    },

    "4672": {
        "meaning": "Special privileges assigned to new logon",
        "importance": "Important when an administrator account logs in",
        "risk": "MEDIUM"
    },

    "4688": {
        "meaning": "New process created",
        "importance": "Useful for investigating suspicious programs or commands",
        "risk": "MEDIUM"
    },

    "4697": {
        "meaning": "Service installed",
        "importance": "Can indicate installation of a new service",
        "risk": "HIGH"
    },

    "4720": {
        "meaning": "User account created",
        "importance": "Important if an unexpected account appears",
        "risk": "HIGH"
    },

    "4728": {
        "meaning": "User added to security-enabled global group",
        "importance": "Can indicate a privilege or group membership change",
        "risk": "HIGH"
    },

    "4732": {
        "meaning": "User added to security-enabled local group",
        "importance": "Can indicate a privilege or group membership change",
        "risk": "HIGH"
    },

    "1102": {
        "meaning": "Security audit log was cleared",
        "importance": "Highly suspicious because evidence may have been removed",
        "risk": "HIGH"
    },

    "7045": {
        "meaning": "New Windows service installed",
        "importance": "Useful for detecting persistence or unauthorized software",
        "risk": "HIGH"
    },

    "104": {
        "meaning": "System event log was cleared",
        "importance": "May indicate an attempt to remove evidence",
        "risk": "HIGH"
    }
}


# ============================================================
# Risk priority
# ============================================================

RISK_PRIORITY = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3
}


# ============================================================
# Event Log Analyzer
# ============================================================

def analyze_event_log(event_log_path):

    """
    Analyze a text-based Windows Event Log sample.

    Detects important Windows Event IDs and returns:
        - detected events
        - event counts
        - findings
        - overall risk level
    """

    path = Path(event_log_path)

    # --------------------------------------------------------
    # Check file
    # --------------------------------------------------------

    if not path.exists():

        return {
            "status": "ERROR",
            "message": f"Event log file does not exist: {path}",
            "risk_level": "LOW",
            "findings": [],
            "events": []
        }

    if not path.is_file():

        return {
            "status": "ERROR",
            "message": f"Specified path is not a file: {path}",
            "risk_level": "LOW",
            "findings": [],
            "events": []
        }

    # --------------------------------------------------------
    # Read event log
    # --------------------------------------------------------

    try:

        content = path.read_text(
            encoding="utf-8",
            errors="ignore"
        )

    except Exception as e:

        return {
            "status": "ERROR",
            "message": f"Unable to read event log: {e}",
            "risk_level": "LOW",
            "findings": [],
            "events": []
        }

    # --------------------------------------------------------
    # Detect Event IDs
    # --------------------------------------------------------

    detected_events = []
    findings = []

    highest_risk = "LOW"

    for event_id, details in EVENT_DEFINITIONS.items():

        # Match Event ID more accurately.
        #
        # Examples supported:
        # Event ID: 4624
        # EventID=4624
        # Event ID 4624
        # ID: 4624
        #

        pattern = rf"""
            (?:
                Event\s*ID
                |
                EventID
                |
                \bID
            )
            \s*
            [:=]?
            \s*
            {re.escape(event_id)}
            \b
        """

        matches = re.findall(
            pattern,
            content,
            flags=re.IGNORECASE | re.VERBOSE
        )

        count = len(matches)

        if count > 0:

            detected_events.append({
                "event_id": event_id,
                "meaning": details["meaning"],
                "importance": details["importance"],
                "risk": details["risk"],
                "count": count
            })

            findings.append(
                f"Event ID {event_id} detected "
                f"({count} occurrence(s)): "
                f"{details['meaning']}. "
                f"{details['importance']}."
            )

            # Update highest risk
            if (
                RISK_PRIORITY[details["risk"]]
                >
                RISK_PRIORITY[highest_risk]
            ):
                highest_risk = details["risk"]

    # --------------------------------------------------------
    # Return result
    # --------------------------------------------------------

    return {
        "status": "SUCCESS",
        "file": str(path),
        "risk_level": highest_risk,
        "events": detected_events,
        "findings": findings
    }
