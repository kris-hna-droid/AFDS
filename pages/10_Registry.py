import streamlit as st
from pathlib import Path


# =====================================================
# PAGE CONFIGURATION
# =====================================================

st.set_page_config(
    page_title="Registry Analysis",
    page_icon="🗂️",
    layout="wide"
)


# =====================================================
# PROJECT PATH
# =====================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# =====================================================
# LOAD CSS
# =====================================================

def load_css():

    css_file = PROJECT_ROOT / "assets" / "style.css"

    if css_file.exists():

        with open(
            css_file,
            "r",
            encoding="utf-8"
        ) as f:

            st.markdown(
                f"<style>{f.read()}</style>",
                unsafe_allow_html=True
            )

    else:

        st.warning(
            "CSS file not found: assets/style.css"
        )


load_css()


# =====================================================
# LOAD REGISTRY ANALYZER
# =====================================================

try:

    from modules.registry_analyzer import analyze_registry

except ImportError:

    analyze_registry = None


# =====================================================
# SIDEBAR
# =====================================================

logo_path = PROJECT_ROOT / "assets" / "afds_logo.png"

if logo_path.exists():

    st.sidebar.image(
        str(logo_path),
        width=100
    )

st.sidebar.title("AFDS")

st.sidebar.caption(
    "Anti-Forensics Detection Suite"
)

st.sidebar.divider()

st.sidebar.success(
    "System Status: Ready"
)


# =====================================================
# PAGE HEADER
# =====================================================

st.title("Registry Analysis")

st.caption(
    "Analyze registry-related evidence for suspicious "
    "changes, USB artifacts, startup entries, and "
    "anti-forensics indicators."
)

st.divider()


# =====================================================
# CHECK EVIDENCE
# =====================================================

file_path = st.session_state.get(
    "evidence_path",
    ""
)


if not file_path:

    st.warning(
        "Please load evidence from the Evidence page first."
    )

    st.page_link(
        "pages/1_Evidence.py",
        label="Go to Evidence Management"
    )

    st.stop()


path = Path(file_path)


# =====================================================
# VERIFY EVIDENCE
# =====================================================

if not path.exists():

    st.error(
        "The selected evidence path does not exist."
    )

    st.stop()


# =====================================================
# EVIDENCE INFORMATION
# =====================================================

with st.container(border=True):

    st.subheader("Evidence Information")

    col1, col2 = st.columns(2)

    with col1:

        st.write("**Evidence Path**")

        st.code(
            str(path)
        )

    with col2:

        if path.is_file():

            st.write("**Evidence Type**")

            st.info("File")

            size = path.stat().st_size

            st.metric(
                "Size",
                f"{size / 1024:.2f} KB"
            )

        elif path.is_dir():

            st.write("**Evidence Type**")

            st.info("Folder")


st.divider()


# =====================================================
# ANALYZE BUTTON
# =====================================================

with st.container(border=True):

    st.subheader("Registry Analysis")

    st.write(
        "Run the Registry analysis against the selected evidence."
    )

    analyze_button = st.button(
        "Analyze Registry",
        use_container_width=True
    )


# =====================================================
# RUN ANALYSIS
# =====================================================

if analyze_button:

    if analyze_registry is None:

        st.error(
            "Registry analyzer could not be loaded."
        )

        st.info(
            "Check that modules/registry_analyzer.py exists."
        )

    else:

        with st.spinner(
            "Analyzing Registry evidence..."
        ):

            try:

                # IMPORTANT:
                # Pass the selected evidence path
                # to the analyzer.
                result = analyze_registry(
                    str(path)
                )

                # Make sure result is a dictionary
                if not isinstance(result, dict):

                    result = {
                        "risk_level": "LOW",
                        "registry_keys": 0,
                        "suspicious_entries": [],
                        "findings": [
                            "Registry analyzer returned an invalid result."
                        ]
                    }

            except Exception as e:

                result = {

                    "risk_level": "ERROR",

                    "registry_keys": 0,

                    "suspicious_entries": [],

                    "findings": [
                        f"Registry analysis failed: {str(e)}"
                    ],

                    "error": str(e)

                }

        # Save result for Dashboard and Reports
        st.session_state["registry_result"] = result

        if result.get("risk_level") == "ERROR":

            st.error(
                "Registry analysis could not be completed."
            )

        else:

            st.success(
                "Registry Analysis Completed"
            )


st.divider()


# =====================================================
# GET STORED RESULT
# =====================================================

result = st.session_state.get(
    "registry_result",
    {
        "risk_level": "LOW",
        "registry_keys": 0,
        "suspicious_entries": [],
        "findings": []
    }
)


# =====================================================
# RESULT SUMMARY
# =====================================================

with st.container(border=True):

    st.subheader("Registry Analysis Summary")

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "Risk Level",
            result.get(
                "risk_level",
                "LOW"
            )
        )

    with col2:

        st.metric(
            "Registry Keys",
            result.get(
                "registry_keys",
                0
            )
        )

    with col3:

        suspicious_entries = result.get(
            "suspicious_entries",
            []
        )

        st.metric(
            "Suspicious Entries",
            len(suspicious_entries)
        )


st.divider()


# =====================================================
# SUSPICIOUS REGISTRY ENTRIES
# =====================================================

with st.container(border=True):

    st.subheader(
        "Suspicious Registry Entries"
    )

    entries = result.get(
        "suspicious_entries",
        []
    )

    if entries:

        for entry in entries:

            st.code(
                str(entry)
            )

    else:

        st.success(
            "No suspicious registry entries detected."
        )


st.divider()


# =====================================================
# FINDINGS
# =====================================================

with st.container(border=True):

    st.subheader(
        "Analysis Findings"
    )

    findings = result.get(
        "findings",
        []
    )

    if findings:

        for finding in findings:

            if result.get("risk_level") == "ERROR":

                st.error(
                    str(finding)
                )

            else:

                st.warning(
                    str(finding)
                )

    else:

        st.success(
            "No suspicious registry activity detected."
        )


st.divider()


# =====================================================
# SESSION STATE STATUS
# =====================================================

if "registry_result" in st.session_state:

    st.info(
        "Registry analysis has been stored for the "
        "Risk Dashboard and Reports pages."
    )


st.divider()


# =====================================================
# NAVIGATION
# =====================================================

with st.container(border=True):

    st.subheader("Next Steps")

    col1, col2 = st.columns(2)

    with col1:

        st.page_link(
            "pages/11_Disk_Wiping.py",
            label="Next: Disk Wiping Analysis"
        )

    with col2:

        st.page_link(
            "pages/12_Risk_Dashboard.py",
            label="Go to Risk Dashboard"
        )


st.divider()


# =====================================================
# FOOTER
# =====================================================

st.caption(
    "AFDS Version 1.0 | Digital Forensics Investigation Platform"
)