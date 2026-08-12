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
    from modules.browser_history_analyzer import analyze_browser_history
except ImportError:
    analyze_browser_history = None


st.set_page_config(
    page_title="Browser History Analysis",
    page_icon="🌐",
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

# =====================================================
# HEADER
# =====================================================

st.title("Browser History Analysis")

st.write(
    "Analyze browser history for suspicious websites and browsing activity."
)

st.divider()

# =====================================================
# CHECK EVIDENCE
# =====================================================

file_path = st.session_state.get("evidence_path", "")

if not file_path:

    st.warning(
        "No evidence selected.\n\nPlease load evidence from the Evidence page."
    )

    st.stop()

path = Path(file_path)

st.success("Evidence Loaded")

st.code(str(path))

st.divider()

# =====================================================
# ANALYZE BUTTON
# =====================================================

if st.button(
    "Analyze Browser History",
    use_container_width=True
):

    if analyze_browser_history is None:

        st.error("browser_history_analyzer.py not found.")

    else:

        with st.spinner("Analyzing browser history..."):

            try:

                result = analyze_browser_history(str(path))

            except Exception as e:

                result = {
                    "risk_level": "LOW",
                    "visited_sites": 0,
                    "suspicious_entries": [],
                    "findings": [str(e)]
                }

        st.session_statebrowser_result = result

        st.success("Browser History Analysis Completed")

st.divider()

# =====================================================
# DISPLAY RESULTS
# =====================================================

result = st.session_state.get(
    "browser_result",
    {
        "risk_level": "LOW",
        "visited_sites": 0,
        "suspicious_entries": [],
        "findings": []
    }
)

col1, col2, col3 = st.columns(3)

with col1:
    st.metric(
        "Risk Level",
        result.get("risk_level", "LOW")
    )

with col2:
    st.metric(
        "Visited Sites",
        result.get("visited_sites", 0)
    )

with col3:
    st.metric(
        "Suspicious Entries",
        len(result.get("suspicious_entries", []))
    )

st.divider()

# =====================================================
# SUSPICIOUS ENTRIES
# =====================================================

st.subheader("Suspicious Browser Entries")

entries = result.get("suspicious_entries", [])

if entries:

    for entry in entries:
        st.code(entry)

else:

    st.success(
        "No suspicious browsing activity detected."
    )

st.divider()

# =====================================================
# FINDINGS
# =====================================================

st.subheader("Analysis Findings")

findings = result.get("findings", [])

if findings:

    for finding in findings:
        st.warning(finding)

else:

    st.success(
        "No browser history anomalies detected."
    )

st.divider()

st.info(
    "Browser history analysis has been stored for the Risk Dashboard and Reports pages."
)

st.divider()

col1, col2 = st.columns(2)

with col1:
    st.page_link(
        "pages/7_Browser_History.py",
        label="Start Browser History Analysis"
    )

with col2:
    st.page_link(
        "pages/8_Encryption.py",
        label="Go to Encryption"
    )

st.divider()

st.caption(
    "AFDS Version 1.0 | Digital Forensics Investigation Platform"
)