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
    from modules.usb_analyzer import analyze_usb
except ImportError:
    analyze_usb = None


st.set_page_config(
    page_title="USB Artifact Detection",
    page_icon="💾",
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

st.title("USB Artifact Detection")

st.write(
    "Analyze USB connection history and detect suspicious removable device activity."
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
    "Analyze USB Artifacts",
    use_container_width=True
):

    if analyze_usb is None:

        st.error("usb_analyzer.py not found.")

    else:

        with st.spinner("Analyzing USB artifacts..."):

            try:

                result = analyze_usb()

            except Exception as e:

                result = {
                    "risk_level": "LOW",
                    "connected_devices": [],
                    "findings": [str(e)]
                }

        st.session_state.usb_result = result

        st.success("USB Analysis Completed")

st.divider()

# =====================================================
# DISPLAY RESULT
# =====================================================

result = st.session_state.get(
    "usb_result",
    {
        "risk_level": "LOW",
        "connected_devices": [],
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
        "USB Devices",
        len(result.get("connected_devices", []))
    )

st.divider()

# =====================================================
# CONNECTED DEVICES
# =====================================================

st.subheader("Connected USB Devices")

devices = result.get("connected_devices", [])

if devices:

    for device in devices:

        st.info(device)

else:

    st.success(
        "No USB devices detected."
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
        "No suspicious USB activity detected."
    )

st.divider()

st.info(
    "USB analysis result has been stored for the Risk Dashboard and Reports pages."
)

st.divider()

col1, col2 = st.columns(2)

with col1:
    st.page_link(
        "pages/5_USB_Artifacts.py",
        label="Start USB Artifacts Analysis"
    )

with col2:
    st.page_link(
        "pages/6_File_Detection.py",
        label="Go to File Detection"
    )

st.divider()

st.caption(
    "AFDS Version 1.0 | Digital Forensics Investigation Platform"
)