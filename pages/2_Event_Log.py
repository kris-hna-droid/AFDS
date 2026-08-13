import streamlit as st
from pathlib import Path

def load_css():

    css_file = Path("assets/style.css")

    with open(css_file) as f:

        st.markdown(
            f"<style>{f.read()}</style>",
            unsafe_allow_html=True
        )

load_css()

try:
    from modules.event_log_detector import analyze_event_log
except ImportError:
    analyze_event_log = None

st.set_page_config(
    page_title="Event Log Analysis",
    page_icon="📄",
    layout="wide"
)

st.sidebar.image(
    "assets/afds_logo.png",
    width=100
)

st.sidebar.title("AFDS")

st.sidebar.caption(
    "Anti-Forensics Detection Suite"
)

st.sidebar.divider()

st.sidebar.success("System Status: Ready")

st.title("Event Log Analysis")
st.write(
    "Analyze Windows Event Logs for possible tampering or suspicious modifications."
)

st.divider()

# -----------------------------
# Check Evidence
# -----------------------------

file_path = st.session_state.get("evidence_path", "")

if not file_path:

    st.warning(
        "No evidence selected.\n\nPlease open the **Evidence** page and load an evidence file first."
    )

    st.stop()

path = Path(file_path)

st.success("Evidence Loaded")

st.code(str(path))

st.divider()

# -----------------------------
# Analyze Button
# -----------------------------

if st.button(
    "Analyze Event Log",
    use_container_width=True
):

    if analyze_event_log is None:

        st.error("event_log_detector.py not found.")

    else:

        with st.spinner("Analyzing Event Logs..."):

            try:

                result = analyze_event_log(str(path))

            except Exception as e:

                result = {
                    "risk_level": "LOW",
                    "findings": [str(e)]
                }

        # Save for dashboard/report page
        st.session_state.event_result = result

        st.success("Analysis Completed")

st.divider()

# -----------------------------
# Display Results
# -----------------------------

result = st.session_state.get(
    "event_result",
    {
        "risk_level": "LOW",
        "findings": []
    }
)

col1, col2 = st.columns(2)

with col1:

    st.metric(
        "Risk Level",
        result.get("risk_level", "LOW")
    )

with col2:

    st.metric(
        "Total Findings",
        len(result.get("findings", []))
    )

st.divider()

st.subheader("Analysis Findings")

findings = result.get("findings", [])

if findings:

    for item in findings:

        st.warning(item)

else:

    st.success(
        "No suspicious event log activity detected."
    )

st.divider()

st.info(
    "The analysis result is now available to the Risk Dashboard and Reports pages."
)

st.divider()

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
