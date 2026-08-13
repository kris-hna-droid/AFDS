from pathlib import Path
import xml.etree.ElementTree as ET

import Evtx.Evtx as evtx


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
    "10016": ("DistributedCOM(DCOM) permission-related event", "LOW")
}


RISK_PRIORITY = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3
}


def analyze_event_log(event_log_path):

    path = Path(event_log_path)

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

    events = []
    findings = []
    highest_risk = "LOW"

    try:

        with evtx.Evtx(str(path)) as log:

            for record in log.records():

                try:

                    xml_data = record.xml()

                    root = ET.fromstring(xml_data)

                    system = root.find(
                        ".//{*}System"
                    )

                    if system is None:
                        continue

                    event_id_element = system.find(
                        "{*}EventID"
                    )

                    if event_id_element is None:
                        continue

                    event_id = event_id_element.text

                    if event_id not in EVENT_DEFINITIONS:
                        continue

                    meaning, risk = EVENT_DEFINITIONS[event_id]

                    # Extract timestamp
                    time_element = system.find(
                        "{*}TimeCreated"
                    )

                    timestamp = ""

                    if time_element is not None:
                        timestamp = time_element.attrib.get(
                            "SystemTime",
                            ""
                        )

                    # Extract computer
                    computer_element = system.find(
                        "{*}Computer"
                    )

                    computer = ""

                    if computer_element is not None:
                        computer = computer_element.text or ""

                    events.append({
                        "event_id": event_id,
                        "meaning": meaning,
                        "risk": risk,
                        "timestamp": timestamp,
                        "computer": computer
                    })

                    findings.append(
                        f"Event ID {event_id} detected: "
                        f"{meaning}."
                    )

                    if (
                        RISK_PRIORITY[risk]
                        >
                        RISK_PRIORITY[highest_risk]
                    ):
                        highest_risk = risk

                except Exception:
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

    if not events:

        findings.append(
            "No monitored Windows Event IDs were detected."
        )

    return {
        "status": "SUCCESS",
        "file": str(path),
        "risk_level": highest_risk,
        "events": events,
        "findings": findings,
        "event_count": len(events)
    }
