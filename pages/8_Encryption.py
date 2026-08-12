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
    from modules.encryption_detector import analyze_encryption
except ImportError:
    analyze_encryption = None


st.set_page_config(
    page_title="Encryption Detection",
    page_icon="🔐",
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

st.title("Encryption Detection")

st.write(
    "Detect encrypted files and identify possible anti-forensics encryption techniques."
)

st.divider()

# =====================================================
# CHECK EVIDENCE
# =====================================================

file_path = st.session_state.get("evidence_path", "")

if not file_path:

    st.warning(
        "Please load evidence from the Evidence page first."
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
    "Analyze Encryption",
    use_container_width=True
):

    if analyze_encryption is None:

        st.error("modules/encryption_detector.py not found.")

    else:

        with st.spinner("Detecting encrypted files..."):

            try:

                result = analyze_encryption(str(path))

            except Exception as e:

                result = {
                    "risk_level": "LOW",
                    "encrypted_files": [],
                    "encrypted_count": 0,
                    "findings": [str(e)]
                }

        st.session_state.encryption_result = result

        st.success("Encryption Analysis Completed")

st.divider()

# =====================================================
# DISPLAY RESULTS
# =====================================================

result = st.session_state.get(
    "encryption_result",
    {
        "risk_level": "LOW",
        "encrypted_files": [],
        "encrypted_count": 0,
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
        "Encrypted Files",
        result.get("encrypted_count", 0)
    )

st.divider()

# =====================================================
# ENCRYPTED FILES
# =====================================================

st.subheader("Detected Encrypted Files")

files = result.get("encrypted_files", [])

if files:

    for file in files:

        st.code(file)

else:

    st.success(
        "No encrypted files detected."
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
        "No suspicious encryption activity detected."
    )

st.divider()

st.info(
    "Encryption analysis has been stored for the Risk Dashboard and Reports pages."
)

st.divider()

col1, col2 = st.columns(2)

with col1:
    st.page_link(
        "pages/8_Encryption.py",
        label="Start Encryption"
    )

with col2:
    st.page_link(
        "pages/9_Command_History.py",
        label="Go to Command Histoy Analysis"
    )

st.divider()

st.caption(
    "AFDS Version 1.0 | Digital Forensics Investigation Platform"
)