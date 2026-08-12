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

st.set_page_config(
    page_title="Evidence",
    page_icon="📁",
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

st.title("Evidence Management")
st.write("Select the evidence file or folder that will be used for forensic analysis.")

st.divider()

# Initialize session state
if "evidence_path" not in st.session_state:
    st.session_state.evidence_path = ""

col1, col2 = st.columns([3, 1])

with col1:
    evidence_path = st.text_input(
        "Evidence File / Folder",
        value=st.session_state.evidence_path,
        key="evidence_input"
    )

with col2:
    st.write("")
    st.write("")
    load = st.button(
        "Load Evidence",
        use_container_width=True
    )

if load:

    path = Path(evidence_path)

    if path.exists():

        st.session_state.evidence_path = str(path)  
        st.session_state.file_path = str(path)

        st.success("Evidence loaded successfully.")

    else:

        st.error("The specified path does not exist.")

st.divider()

if st.session_state.evidence_path:

    path = Path(st.session_state.evidence_path)

    st.subheader("Evidence Information")

    col1, col2 = st.columns(2)

    with col1:

        st.write("**Path**")
        st.code(str(path))

        st.write("**Type**")

        if path.is_file():
            st.info("File")

        elif path.is_dir():
            st.info("Folder")

    with col2:

        if path.exists():

            if path.is_file():

                st.write("**Size**")

                size = path.stat().st_size / 1024

                st.metric("KB", f"{size:.2f}")

            st.write("**Status**")

            st.success("Ready for Analysis")

else:

    st.info("No evidence selected.")

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