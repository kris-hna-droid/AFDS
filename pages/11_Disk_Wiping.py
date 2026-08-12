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
    from modules.disk_wiping_detector import analyze_disk_wiping
except ImportError:
    analyze_disk_wiping = None


st.set_page_config(
    page_title="Disk Wiping Detection",
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

st.title("Disk Wiping Detection")

st.write(
    "Detect secure deletion tools and evidence of disk wiping activities."
)

st.divider()

# =====================================================
# CHECK EVIDENCE
# =====================================================

file_path = st.session_state.get("evidence_path", "")

if not file_path:

    st.warning("Please select evidence from the Evidence page first.")

    st.stop()

path = Path(file_path)

st.success("Evidence Loaded")

st.code(str(path))

st.divider()

# =====================================================
# ANALYZE
# =====================================================

if st.button(
    "Analyze Disk Wiping",
    use_container_width=True
):

    if analyze_disk_wiping is None:

        st.error("modules/disk_wiping_detector.py not found.")

    else:

        with st.spinner("Analyzing..."):

            try:

                result = analyze_disk_wiping(str(path))

            except Exception as e:

                result = {
                    "risk_level": "LOW",
                    "wiping_tools": [],
                    "findings": [str(e)]
                }

        st.session_state.disk_result = result

        st.success("Analysis Completed")

st.divider()

# =====================================================
# DISPLAY RESULTS
# =====================================================

result = st.session_state.get(
    "disk_result",
    {
        "risk_level": "LOW",
        "wiping_tools": [],
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
        "Detected Wiping Tools",
        len(result.get("wiping_tools", []))
    )

st.divider()

# =====================================================
# WIPING TOOLS
# =====================================================

st.subheader("Detected Disk Wiping Tools")

tools = result.get("wiping_tools", [])

if tools:

    for tool in tools:

        st.code(tool)

else:

    st.success("No disk wiping tools detected.")

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

    st.success("No evidence of disk wiping detected.")

st.divider()

st.info(
    "Disk wiping analysis has been stored for the Dashboard and Reports pages."
)

st.divider()

col1, col2 = st.columns(2)

with col1:
    st.page_link(
        "pages/11_Disk_Wiping.py",
        label="Start Disk Wiping Analysis"
    )

with col2:
    st.page_link(
        "pages/12_Risk_Dashboard.py",
        label="Go to Risk Dashboard"
    )

st.divider()

st.caption(
    "AFDS Version 1.0 | Digital Forensics Investigation Platform"
)