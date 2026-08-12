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
    from modules.timestamp_analyzer import analyze_timestamps
except ImportError:
    analyze_timestamps = None


st.set_page_config(
    page_title="Timestamp Analysis",
    page_icon="🕒",
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

# ======================================
# Header
# ======================================

st.title("Timestamp Analysis")

st.write(
    "Analyze file timestamps to identify possible timestamp manipulation or anti-forensics activity."
)

st.divider()

# ======================================
# Check Evidence
# ======================================

file_path = st.session_state.get("evidence_path", "")

if not file_path:

    st.warning(
        "No evidence selected.\n\nPlease load an evidence file from the Evidence page."
    )

    st.stop()

path = Path(file_path)

st.success("Evidence Loaded")

st.code(str(path))

st.divider()

# ======================================
# Analyze Button
# ======================================

if st.button(
    "Analyze Timestamp",
    use_container_width=True
):

    if analyze_timestamps is None:

        st.error("timestamp_analyzer.py not found.")

    else:

        with st.spinner("Analyzing timestamps..."):

            try:

                result = analyze_timestamps(path)

            except Exception as e:

                result = {
                    "risk_level": "LOW",
                    "created": "Not Available",
                    "modified": "Not Available",
                    "accessed": "Not Available",
                    "findings": [str(e)]
                }

        st.session_state.timestamp_result = result

        st.success("Timestamp Analysis Completed")

st.divider()

# ======================================
# Display Results
# ======================================

result = st.session_state.get(
    "timestamp_result",
    {
        "risk_level": "LOW",
        "created": "Not Available",
        "modified": "Not Available",
        "accessed": "Not Available",
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
        "Findings",
        len(result.get("findings", []))
    )

st.divider()

# ======================================
# Timestamp Information
# ======================================

with st.container(border=True):

    st.subheader("Timestamp Analysis")

    st.metric(
        "Risk Level",
        result["risk_level"]
    )

c1, c2, c3 = st.columns(3)

with c1:

    st.info(
        f"Created\n\n{result.get('created', 'Not Available')}"
    )

with c2:

    st.info(
        f"Modified\n\n{result.get('modified', 'Not Available')}"
    )

with c3:

    st.info(
        f"Accessed\n\n{result.get('accessed', 'Not Available')}"
    )

st.divider()

# ======================================
# Findings
# ======================================

st.subheader("Analysis Findings")

findings = result.get("findings", [])

if findings:

    for finding in findings:

        st.warning(finding)

else:

    st.success(
        "No suspicious timestamp activity detected."
    )

st.divider()

st.info(
    "The timestamp analysis result has been stored for the Risk Dashboard and Reports pages."
)

st.divider()

col1, col2 = st.columns(2)

with col1:
    st.page_link(
        "pages/3_Timestamp.py",
        label="Start Timestamp Analysis"
    )

with col2:
    st.page_link(
        "pages/4_Metadata.py",
        label="Go to Metadata Analysis"
    )

st.divider()

st.caption(
    "AFDS Version 1.0 | Digital Forensics Investigation Platform"
)