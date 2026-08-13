from pathlib import Path
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime

import Evtx.Evtx as evtx


# =====================================================
# IMPORTANT WINDOWS EVENT IDS
# =====================================================

EVENT_DEFINITIONS = {
    "4624": ("Successful logon", "LOW"),
    "4625": ("Failed logon", "MEDIUM"),
    "4634": ("Account logoff", "LOW"),
    "4648": ("Logon using explicit credentials", "MEDIUM"),
    "4672": ("Special privileges assigned to new logon", "MEDIUM"),
    "4688": ("New process created", "MEDIUM"),
    "4697": ("Service installed", "HIGH"),
    "4720": ("User account created", "HIGH"),
    "4728": ("User added to security-enabled global group", "HIGH"),
    "4732": ("User added to security-enabled local group", "HIGH"),
    "1102": ("Security audit log was cleared", "HIGH"),
    "7045": ("New Windows service installed", "HIGH"),
    "104": ("System event log was cleared", "HIGH"),
    "10016": ("DistributedCOM permission-related event", "LOW"),
    "300": ("Office related alert or notification", "LOW")
}


RISK_PRIORITY = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3
}


# =====================================================
# SAFE XML TEXT FUNCTION
# =====================================================

def get_text(parent, path):

    element = parent.find(path)

    if element is None:
        return ""

    return element.text or ""


# =====================================================
# EXTRACT EVENT DATA
# =====================================================

def extract_event_data(root):

    system = root.find(".//{*}System")

    if system is None:
        return None

    event_id_element = system.find("{*}EventID")

    if event_id_element is None:
        return None

    event_id = event_id_element.text

    if not event_id:
        return None

    event_id = event_id.strip()

    # Ignore events that are not part of our monitored list
    if event_id not in EVENT_DEFINITIONS:
        return None

    meaning, risk = EVENT_DEFINITIONS[event_id]

    # -------------------------------------------------
    # Timestamp
    # -------------------------------------------------

    time_element = system.find("{*}TimeCreated")

    timestamp = ""

    if time_element is not None:
        timestamp = time_element.attrib.get(
            "SystemTime",
            ""
        )

    # -------------------------------------------------
    # Computer
    # -------------------------------------------------

    computer = get_text(
        system,
        "{*}Computer"
    )

    # -------------------------------------------------
    # Provider
    # -------------------------------------------------

    provider_element = system.find("{*}Provider")

    provider = ""

    if provider_element is not None:
        provider = provider_element.attrib.get(
            "Name",
            ""
        )

    # -------------------------------------------------
    # Event Record ID
    # -------------------------------------------------

    record_id = get_text(
        system,
        "{*}EventRecordID"
    )

    # -------------------------------------------------
    # Event Data
    # -------------------------------------------------

    event_data = {}

    data_elements = root.findall(
        ".//{*}EventData/{*}Data"
    )

    for data in data_elements:

        name = data.attrib.get(
            "Name",
            ""
        )

        value = data.text or ""

        if name:
            event_data[name] = value

    # -------------------------------------------------
    # Common account fields
    # -------------------------------------------------

    username = (
        event_data.get("TargetUserName")
        or event_data.get("SubjectUserName")
        or event_data.get("AccountName")
        or ""
    )

    domain = (
        event_data.get("TargetDomainName")
        or event_data.get("SubjectDomainName")
        or ""
    )

    # -------------------------------------------------
    # IP address
    # -------------------------------------------------

    ip_address = (
        event_data.get("IpAddress")
        or event_data.get("ClientAddress")
        or ""
    )

    # -------------------------------------------------
    # Process information - Event 4688
    # -------------------------------------------------

    process_name = (
        event_data.get("NewProcessName")
        or event_data.get("ProcessName")
        or ""
    )

    command_line = (
        event_data.get("CommandLine")
        or ""
    )

    # -------------------------------------------------
    # Service information - 7045 / 4697
    # -------------------------------------------------

    service_name = (
        event_data.get("ServiceName")
        or ""
    )

    service_file = (
        event_data.get("ImagePath")
        or event_data.get("ServiceFileName")
        or ""
    )

    return {
        "event_id": event_id,
        "meaning": meaning,
        "risk": risk,
        "timestamp": timestamp,
        "computer": computer,
        "provider": provider,
        "record_id": record_id,
        "username": username,
        "domain": domain,
        "ip_address": ip_address,
        "process_name": process_name,
        "command_line": command_line,
        "service_name": service_name,
        "service_file": service_file
    }


# =====================================================
# MAIN ANALYZER
# =====================================================

def analyze_event_log(event_log_path):

    path = Path(event_log_path)

    # -------------------------------------------------
    # FILE VALIDATION
    # -------------------------------------------------

    if not path.exists():

        return {
            "status": "ERROR",
            "risk_level": "LOW",
            "events": [],
            "findings": [
                f"Event log file does not exist: {path}"
            ]
        }

    if not path.is_file():

        return {
            "status": "ERROR",
            "risk_level": "LOW",
            "events": [],
            "findings": [
                "The supplied evidence is not a file."
            ]
        }

    # -------------------------------------------------
    # VARIABLES
    # -------------------------------------------------

    events = []

    findings = []

    event_counter = Counter()

    total_records = 0

    highest_risk = "LOW"

    # -------------------------------------------------
    # READ EVTX
    # -------------------------------------------------

    try:

        with evtx.Evtx(str(path)) as log:

            for record in log.records():

                total_records += 1

                try:

                    xml_data = record.xml()

                    root = ET.fromstring(
                        xml_data
                    )

                    event = extract_event_data(
                        root
                    )

                    if event is None:
                        continue

                    events.append(event)

                    event_id = event["event_id"]

                    event_counter[event_id] += 1

                    risk = event["risk"]

                    if (
                        RISK_PRIORITY[risk]
                        >
                        RISK_PRIORITY[highest_risk]
                    ):

                        highest_risk = risk

                except Exception:

                    # Skip malformed individual records
                    continue

    except Exception as e:

        return {
            "status": "ERROR",
            "risk_level": "LOW",
            "events": [],
            "findings": [
                f"Unable to parse EVTX file: {e}"
            ]
        }

    # =================================================
    # SORT TIMELINE
    # =================================================

    events.sort(
        key=lambda x: x.get(
            "timestamp",
            ""
        )
    )

    # =================================================
    # BUILD FORENSIC FINDINGS
    # =================================================

    # -------------------------------------------------
    # No monitored events
    # -------------------------------------------------

    if not events:

        findings.append(
            "No monitored Windows Event IDs were detected."
        )

    # -------------------------------------------------
    # Event 1102
    # -------------------------------------------------

    if event_counter["1102"] > 0:

        findings.append(
            f"Event ID 1102 detected "
            f"{event_counter['1102']} time(s): "
            "Security audit log clearing activity detected."
        )

    # -------------------------------------------------
    # Event 104
    # -------------------------------------------------

    if event_counter["104"] > 0:

        findings.append(
            f"Event ID 104 detected "
            f"{event_counter['104']} time(s): "
            "System event log clearing activity detected."
        )

    # -------------------------------------------------
    # Failed logons
    # -------------------------------------------------

    failed_logons = event_counter["4625"]

    if failed_logons > 0:

        findings.append(
            f"{failed_logons} failed logon event(s) "
            "detected (Event ID 4625)."
        )

        if failed_logons >= 10:

            findings.append(
                "A high number of failed logons was detected. "
                "This may warrant investigation for unusual "
                "authentication activity."
            )

    # -------------------------------------------------
    # Successful logons
    # -------------------------------------------------

    successful_logons = event_counter["4624"]

    if successful_logons > 0:

        findings.append(
            f"{successful_logons} successful logon event(s) "
            "detected."
        )

    # -------------------------------------------------
    # Explicit credentials
    # -------------------------------------------------

    if event_counter["4648"] > 0:

        findings.append(
            f"{event_counter['4648']} explicit-credential "
            "logon event(s) detected."
        )

    # -------------------------------------------------
    # Special privileges
    # -------------------------------------------------

    if event_counter["4672"] > 0:

        findings.append(
            f"{event_counter['4672']} privileged logon "
            "event(s) detected."
        )

    # -------------------------------------------------
    # Process creation
    # -------------------------------------------------

    if event_counter["4688"] > 0:

        findings.append(
            f"{event_counter['4688']} process creation "
            "event(s) detected."
        )

    # -------------------------------------------------
    # Service installation
    # -------------------------------------------------

    service_events = (
        event_counter["4697"]
        + event_counter["7045"]
    )

    if service_events > 0:

        findings.append(
            f"{service_events} service installation "
            "event(s) detected."
        )

    # -------------------------------------------------
    # User creation
    # -------------------------------------------------

    if event_counter["4720"] > 0:

        findings.append(
            f"{event_counter['4720']} user account "
            "creation event(s) detected."
        )

    # -------------------------------------------------
    # Security group changes
    # -------------------------------------------------

    group_events = (
        event_counter["4728"]
        + event_counter["4732"]
    )

    if group_events > 0:

        findings.append(
            f"{group_events} security group membership "
            "change event(s) detected."
        )

    # =================================================
    # RISK OVERRIDE
    # =================================================

    # Log clearing is always treated as HIGH
    if (
        event_counter["1102"] > 0
        or event_counter["104"] > 0
    ):

        highest_risk = "HIGH"

    # Service installation / account changes are HIGH
    elif (
        event_counter["7045"] > 0
        or event_counter["4697"] > 0
        or event_counter["4720"] > 0
        or event_counter["4728"] > 0
        or event_counter["4732"] > 0
    ):

        highest_risk = "HIGH"

    # =================================================
    # COUNTS BY RISK
    # =================================================

    low_count = sum(
        1 for event in events
        if event["risk"] == "LOW"
    )

    medium_count = sum(
        1 for event in events
        if event["risk"] == "MEDIUM"
    )

    high_count = sum(
        1 for event in events
        if event["risk"] == "HIGH"
    )

    # =================================================
    # RETURN RESULT
    # =================================================

    return {

        "status": "SUCCESS",

        "file": str(path),

        "risk_level": highest_risk,

        "total_records_scanned": total_records,

        "event_count": len(events),

        "suspicious_event_count": sum(
            1 for event in events
            if event["risk"] in ["MEDIUM", "HIGH"]
        ),

        "risk_counts": {
            "LOW": low_count,
            "MEDIUM": medium_count,
            "HIGH": high_count
        },

        "event_counts": dict(
            event_counter
        ),

        "events": events,

        "findings": findings
    }
