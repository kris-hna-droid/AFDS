import streamlit as st
from pathlib import Path

from modules.event_log_detector import analyze_event_log


# =====================================================
# CSS
# =====================================================

def load_css():

    css_file = Path("assets/style.css")

    if css_file.exists():

        with open(css_file, encoding="utf-8") as f:

            st.markdown(
                f"<style>{f.read()}</style>",
                unsafe_allow_html=True
            )


load_css()


# =====================================================
# PAGE CONFIG
# =====================================================

st.set_page_config(
    page_title="Event Log Analysis",
    page_icon="📄",
    layout="wide"
)


# =====================================================
# SIDEBAR
# =====================================================

st.sidebar.image(
    "assets/afds_logo.png",
    width=100
)

st.sidebar.title("AFDS")

st.sidebar.caption(
    "Anti-Forensics Detection Suite"
)

st.sidebar.divider()

st.sidebar.success(
    "System Status: Ready"
)


# =====================================================
# HEADER
# =====================================================

st.title("Event Log Analysis")

st.write(
    "Analyze Windows EVTX Event Logs for suspicious "
    "authentication, privilege, process, service, "
    "account, and log-clearing activity."
)

st.divider()


# =====================================================
# CHECK EVIDENCE
# =====================================================

file_path = st.session_state.get(
    "evidence_path",
    ""
)

if not file_path:

    st.warning(
        "No evidence selected.\n\n"
        "Please open the Evidence page and load an "
        "EVTX evidence file first."
    )

    st.stop()


path = Path(file_path)

if not path.exists():

    st.error(
        f"Evidence file does not exist:\n{path}"
    )

    st.stop()


st.success("Evidence Loaded")

st.code(str(path))

st.divider()


# =====================================================
# FILE TYPE CHECK
# =====================================================

if path.suffix.lower() != ".evtx":

    st.warning(
        "The selected file is not an EVTX file. "
        "For Event Log Analysis, select a Windows "
        ".evtx Event Log file."
    )


# =====================================================
# ANALYZE BUTTON
# =====================================================

if st.button(
    "Analyze Event Log",
    use_container_width=True
):

    with st.spinner(
        "Reading and analyzing Windows Event Log..."
    ):

        try:

            result = analyze_event_log(
                str(path)
            )

        except Exception as e:

            result = {

                "status": "ERROR",

                "risk_level": "LOW",

                "events": [],

                "findings": [
                    f"Event Log analysis failed: {e}"
                ]

            }

    # Save complete result
    st.session_state.event_result = result

    if result.get("status") == "SUCCESS":

        st.success(
            "Event Log Analysis Completed Successfully"
        )

    else:

        st.error(
            "Event Log Analysis failed."
        )


st.divider()


# =====================================================
# GET RESULT
# =====================================================

result = st.session_state.get(
    "event_result",
    {
        "status": "NOT_ANALYZED",
        "risk_level": "LOW",
        "total_records_scanned": 0,
        "event_count": 0,
        "suspicious_event_count": 0,
        "risk_counts": {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0
        },
        "event_counts": {},
        "events": [],
        "findings": []
    }
)


# =====================================================
# OVERALL RISK
# =====================================================

st.subheader("Overall Assessment")

col1, col2, col3, col4 = st.columns(4)

with col1:

    st.metric(
        "Risk Level",
        result.get(
            "risk_level",
            "LOW"
        )
    )

with col2:

    st.metric(
        "Records Scanned",
        result.get(
            "total_records_scanned",
            0
        )
    )

with col3:

    st.metric(
        "Monitored Events",
        result.get(
            "event_count",
            0
        )
    )

with col4:

    st.metric(
        "Suspicious Events",
        result.get(
            "suspicious_event_count",
            0
        )
    )


st.divider()


# =====================================================
# RISK COUNTS
# =====================================================

st.subheader("Risk Distribution")

risk_counts = result.get(
    "risk_counts",
    {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0
    }
)

col1, col2, col3 = st.columns(3)

with col1:

    st.metric(
        "LOW",
        risk_counts.get(
            "LOW",
            0
        )
    )

with col2:

    st.metric(
        "MEDIUM",
        risk_counts.get(
            "MEDIUM",
            0
        )
    )

with col3:

    st.metric(
        "HIGH",
        risk_counts.get(
            "HIGH",
            0
        )
    )


st.divider()


# =====================================================
# EVENT ID COUNTS
# =====================================================

st.subheader(
    "Windows Event ID Statistics"
)

event_counts = result.get(
    "event_counts",
    {}
)

if event_counts:

    table = []

    for event_id, count in sorted(
        event_counts.items(),
        key=lambda x: int(x[0])
    ):

        table.append({

            "Event ID": event_id,

            "Meaning": (
                result["events"][
                    next(
                        (
                            i for i, e
                            in enumerate(
                                result["events"]
                            )
                            if e["event_id"] == event_id
                        ),
                        0
                    )
                ].get(
                    "meaning",
                    "Unknown"
                )
                if result.get("events")
                else "Unknown"
            ),

            "Count": count

        })

    st.dataframe(
        table,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No monitored Event IDs detected."
    )


st.divider()


# =====================================================
# IMPORTANT EVENTS
# =====================================================

st.subheader(
    "Important Event Activity"
)

important_ids = [
    "1102",
    "104",
    "7045",
    "4697",
    "4720",
    "4728",
    "4732",
    "4688",
    "4672",
    "4648",
    "4625"
]

important_found = False

for event_id in important_ids:

    count = event_counts.get(
        event_id,
        0
    )

    if count > 0:

        important_found = True

        matching_event = next(
            (
                event
                for event in result.get(
                    "events",
                    []
                )
                if event.get(
                    "event_id"
                ) == event_id
            ),
            {}
        )

        st.warning(
            f"Event ID {event_id} | "
            f"{matching_event.get('meaning', '')} | "
            f"Occurrences: {count} | "
            f"Risk: {matching_event.get('risk', 'UNKNOWN')}"
        )


if not important_found:

    st.success(
        "No high-priority monitored events detected."
    )


st.divider()


# =====================================================
# FORENSIC TIMELINE
# =====================================================

st.subheader(
    "Forensic Event Timeline"
)

events = result.get(
    "events",
    []
)

if events:

    timeline = []

    for event in events:

        timeline.append({

            "Timestamp": event.get(
                "timestamp",
                ""
            ),

            "Event ID": event.get(
                "event_id",
                ""
            ),

            "Meaning": event.get(
                "meaning",
                ""
            ),

            "Risk": event.get(
                "risk",
                ""
            ),

            "Username": event.get(
                "username",
                ""
            ),

            "Computer": event.get(
                "computer",
                ""
            ),

            "IP Address": event.get(
                "ip_address",
                ""
            ),

            "Provider": event.get(
                "provider",
                ""
            )

        })

    st.dataframe(
        timeline,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No monitored events available for the timeline."
    )


st.divider()


# =====================================================
# PROCESS ANALYSIS
# =====================================================

st.subheader(
    "Process Creation Analysis"
)

process_events = [

    event
    for event in events
    if event.get("event_id") == "4688"

]

if process_events:

    process_table = []

    for event in process_events:

        process_table.append({

            "Timestamp": event.get(
                "timestamp",
                ""
            ),

            "User": event.get(
                "username",
                ""
            ),

            "Process": event.get(
                "process_name",
                ""
            ),

            "Command Line": event.get(
                "command_line",
                ""
            ),

            "Computer": event.get(
                "computer",
                ""
            )

        })

    st.dataframe(
        process_table,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No Event ID 4688 process creation events detected."
    )


st.divider()


# =====================================================
# SERVICE ANALYSIS
# =====================================================

st.subheader(
    "Windows Service Installation Analysis"
)

service_events = [

    event
    for event in events
    if event.get("event_id")
    in ["4697", "7045"]

]

if service_events:

    service_table = []

    for event in service_events:

        service_table.append({

            "Timestamp": event.get(
                "timestamp",
                ""
            ),

            "Event ID": event.get(
                "event_id",
                ""
            ),

            "Service Name": event.get(
                "service_name",
                ""
            ),

            "Service File": event.get(
                "service_file",
                ""
            ),

            "Risk": event.get(
                "risk",
                ""
            )

        })

    st.dataframe(
        service_table,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No service installation events detected."
    )


st.divider()


# =====================================================
# ACCOUNT / LOGIN ANALYSIS
# =====================================================

st.subheader(
    "Authentication Activity"
)

authentication_ids = [
    "4624",
    "4625",
    "4648",
    "4672"
]

authentication_events = [

    event
    for event in events
    if event.get("event_id")
    in authentication_ids

]

if authentication_events:

    authentication_table = []

    for event in authentication_events:

        authentication_table.append({

            "Timestamp": event.get(
                "timestamp",
                ""
            ),

            "Event ID": event.get(
                "event_id",
                ""
            ),

            "Meaning": event.get(
                "meaning",
                ""
            ),

            "Username": event.get(
                "username",
                ""
            ),

            "Domain": event.get(
                "domain",
                ""
            ),

            "IP Address": event.get(
                "ip_address",
                ""
            ),

            "Risk": event.get(
                "risk",
                ""
            )

        })

    st.dataframe(
        authentication_table,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No monitored authentication events detected."
    )


st.divider()


# =====================================================
# FINDINGS
# =====================================================

st.subheader(
    "Forensic Findings"
)

findings = result.get(
    "findings",
    []
)

if findings:

    for finding in findings:

        st.warning(
            finding
        )

else:

    st.success(
        "No suspicious event log activity detected."
    )


st.divider()


# =====================================================
# RAW EVENT DETAILS
# =====================================================

st.subheader(
    "Detailed Event Records"
)

if events:

    selected_event = st.selectbox(

        "Select an Event",

        range(
            len(events)
        ),

        format_func=lambda i:
            (
                f"{events[i].get('timestamp', '')} | "
                f"Event ID {events[i].get('event_id', '')} | "
                f"{events[i].get('meaning', '')}"
            )

    )

    event = events[
        selected_event
    ]

    st.json(event)

else:

    st.info(
        "No event records available."
    )


st.divider()


# =====================================================
# INFORMATION
# =====================================================

st.info(
    "Event Log analysis has been stored in session state "
    "for the Risk Dashboard and Reports pages."
)


st.divider()


# =====================================================
# NAVIGATION
# =====================================================

col1, col2 = st.columns(2)

with col1:

    st.page_link(
        "pages/2_Event_Log.py",
        label="Start Event Log Analysis"
    )

with col2:

    st.page_link(
        "pages/3_Timestamp.py",
        label="Go to Timestamp Analysis"
    )


st.divider()


st.caption(
    "AFDS Version 1.0 | Digital Forensics Investigation Platform"
)
