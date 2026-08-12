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
    from modules.deletion_detector import analyze_folder
except ImportError:
    analyze_folder = None


st.set_page_config(
    page_title="File Detection",
    page_icon="📂",
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

st.title("File Detection")

st.write(
    "Analyze the selected evidence folder for suspicious, hidden, empty and abnormal files."
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
    "Analyze Files",
    use_container_width=True
):

    if analyze_folder is None:

        st.error("deletion_detector.py not found.")

    else:

        with st.spinner("Analyzing files..."):

            try:

                result = analyze_folder(str(path))

            except Exception as e:

                result = {
                    "risk_level": "LOW",
                    "total_files": 0,
                    "hidden_files": 0,
                    "empty_files": 0,
                    "large_files": 0,
                    "suspicious_files": [],
                    "findings": [str(e)]
                }

        st.session_state.file_result = result

        st.success("File Analysis Completed")

st.divider()

# =====================================================
# DISPLAY RESULTS
# =====================================================

result = st.session_state.get(
    "file_result",
    {
        "risk_level": "LOW",
        "total_files": 0,
        "hidden_files": 0,
        "empty_files": 0,
        "large_files": 0,
        "suspicious_files": [],
        "findings": []
    }
)

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Risk Level", result.get("risk_level", "LOW"))

with col2:
    st.metric("Total Files", result.get("total_files", 0))

with col3:
    st.metric("Hidden Files", result.get("hidden_files", 0))

with col4:
    st.metric("Empty Files", result.get("empty_files", 0))

st.divider()

col5, col6 = st.columns(2)

with col5:
    st.metric("Large Files", result.get("large_files", 0))

with col6:
    st.metric(
        "Suspicious Files",
        len(result.get("suspicious_files", []))
    )

st.divider()

# =====================================================
# SUSPICIOUS FILES
# =====================================================

st.subheader("Suspicious Files")

files = result.get("suspicious_files", [])

if files:

    for file in files:
        st.code(file)

else:

    st.success("No suspicious files detected.")

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

    st.success("No abnormal file activity detected.")

st.divider()

st.info(
    "File analysis result has been stored for the Risk Dashboard and Reports pages."
)

st.divider()

col1, col2 = st.columns(2)

with col1:
    st.page_link(
        "pages/6_File_Detection.py",
        label="Start File Detection"
    )

with col2:
    st.page_link(
        "pages/7_Browser_History.py",
        label="Go to Timestamp Analysis"
    )