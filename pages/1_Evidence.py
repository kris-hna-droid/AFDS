import streamlit as st
from pathlib import Path
import tempfile
import shutil

# =====================================================
# PAGE CONFIG — MUST COME BEFORE OTHER st COMMANDS
# =====================================================

st.set_page_config(
    page_title="Evidence",
    page_icon="📁",
    layout="wide"
)


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
# SIDEBAR
# =====================================================

logo_file = Path("assets/afds_logo.png")

if logo_file.exists():

    st.sidebar.image(
        str(logo_file),
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

st.title("Evidence Management")

st.write(
    "Upload the evidence file that will be used for forensic analysis."
)

st.divider()


# =====================================================
# INITIALIZE SESSION STATE
# =====================================================

if "evidence_path" not in st.session_state:
    st.session_state.evidence_path = ""

if "evidence_name" not in st.session_state:
    st.session_state.evidence_name = ""

if "evidence_size" not in st.session_state:
    st.session_state.evidence_size = 0


# =====================================================
# EVIDENCE UPLOAD
# =====================================================

st.subheader("Upload Evidence")

uploaded_file = st.file_uploader(
    "Select an evidence file",
    type=None,
    help="Upload a forensic test file such as USB_Artifact_Test_Data.txt"
)


# =====================================================
# LOAD EVIDENCE
# =====================================================

if uploaded_file is not None:

    st.write(
        f"**Selected file:** `{uploaded_file.name}`"
    )

    st.write(
        f"**Size:** `{uploaded_file.size / 1024:.2f} KB`"
    )

    if st.button(
        "Load Evidence",
        use_container_width=True
    ):

        try:

            # Create temporary directory
            temp_dir = tempfile.mkdtemp(
                prefix="afds_evidence_"
            )

            # Prevent unsafe path components
            safe_name = Path(uploaded_file.name).name

            file_path = Path(temp_dir) / safe_name

            # Save uploaded file
            with open(file_path, "wb") as f:

                f.write(
                    uploaded_file.getbuffer()
                )

            # Store path for all AFDS modules
            st.session_state.evidence_path = str(file_path)

            st.session_state.file_path = str(file_path)

            st.session_state.evidence_name = safe_name

            st.session_state.evidence_size = uploaded_file.size

            st.success(
                "Evidence loaded successfully."
            )

        except Exception as e:

            st.error(
                f"Failed to load evidence: {e}"
            )


# =====================================================
# EVIDENCE INFORMATION
# =====================================================

st.divider()

if st.session_state.evidence_path:

    path = Path(
        st.session_state.evidence_path
    )

    st.subheader("Evidence Information")

    col1, col2, col3 = st.columns(3)

    with col1:

        st.write("**Evidence File**")

        st.code(
            st.session_state.evidence_name
        )

    with col2:

        st.write("**Type**")

        st.info("File")

    with col3:

        st.write("**Size**")

        size_kb = (
            st.session_state.evidence_size / 1024
        )

        st.metric(
            "KB",
            f"{size_kb:.2f}"
        )

    st.write("**Temporary Evidence Path**")

    st.code(
        str(path)
    )

    if path.exists():

        st.success(
            "Evidence is ready for forensic analysis."
        )

    else:

        st.error(
            "Evidence file is no longer available."
        )

else:

    st.info(
        "No evidence selected. Upload a file above."
    )


# =====================================================
# NAVIGATION
# =====================================================

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


# =====================================================
# FOOTER
# =====================================================

st.divider()

st.caption(
    "AFDS Version 1.0 | Digital Forensics Investigation Platform"
)
