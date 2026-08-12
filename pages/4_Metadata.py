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
    from modules.metadata_analyzer import analyze_metadata
except ImportError:
    analyze_metadata = None


st.set_page_config(
    page_title="Metadata Analysis",
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

# =====================================================
# HEADER
# =====================================================

st.title("Metadata Analysis")

st.write(
    "Extract and analyze file metadata to identify suspicious modifications or anomalies."
)

st.divider()

# =====================================================
# CHECK EVIDENCE
# =====================================================

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

# =====================================================
# ANALYZE BUTTON
# =====================================================

if st.button(
    "Analyze Metadata",
    use_container_width=True
):

    if analyze_metadata is None:

        st.error("metadata_analyzer.py not found.")

    else:

        with st.spinner("Extracting metadata..."):

            try:

                result = analyze_metadata(str(path))

            except Exception as e:

                result = {
                    "risk_level": "LOW",
                    "file_name": "Unknown",
                    "file_size": "Unknown",
                    "file_extension": "Unknown",
                    "owner": "Unknown",
                    "findings": [str(e)]
                }

        st.session_state.metadata_result = result

        st.success("Metadata Analysis Completed")

st.divider()

# =====================================================
# DISPLAY RESULTS
# =====================================================

result = st.session_state.get(
    "metadata_result",
    {
        "risk_level": "LOW",
        "file_name": "Unknown",
        "file_size": "Unknown",
        "file_extension": "Unknown",
        "owner": "Unknown",
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

# =====================================================
# METADATA DETAILS
# =====================================================

st.subheader("Metadata Information")

c1, c2 = st.columns(2)

with c1:

    st.info(f"File Name\n\n{result.get('file_name', 'Unknown')}")

    st.info(f"File Size\n\n{result.get('file_size', 'Unknown')}")

with c2:

    st.info(f"Extension\n\n{result.get('file_extension', 'Unknown')}")

    st.info(f"Owner\n\n{result.get('owner', 'Unknown')}")

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
        "No suspicious metadata detected."
    )

st.divider()

st.info(
    "The metadata analysis result has been stored for the Risk Dashboard and Reports pages."
)

st.divider()

col1, col2 = st.columns(2)

with col1:
    st.page_link(
        "pages/4_Metadata.py",
        label="Start Metadata Analysis"
    )

with col2:
    st.page_link(
        "pages/5_USB_Artifacts.py",
        label="Go to USB Artifacts Analysis"
    )

st.divider()

st.caption(
    "AFDS Version 1.0 | Digital Forensics Investigation Platform"
)