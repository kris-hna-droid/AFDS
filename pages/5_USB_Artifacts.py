import streamlit as st
from pathlib import Path


# =====================================================
# PAGE CONFIG
# =====================================================

st.set_page_config(
    page_title="USB Artifact Detection",
    page_icon="💾",
    layout="wide"
)


# =====================================================
# LOAD CSS
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
# IMPORT USB ANALYZER
# =====================================================

try:

    from modules import usb_analyzer

    analyzer_available = True

except ImportError as e:

    usb_analyzer = None
    analyzer_available = False
    analyzer_error = str(e)


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

st.sidebar.success(
    "System Status: Ready"
)


# =====================================================
# HEADER
# =====================================================

st.title("USB Artifact Detection")

st.write(
    "Analyze USB connection history and detect suspicious "
    "removable device activity."
)

st.divider()


# =====================================================
# CHECK USB ANALYZER
# =====================================================

if not analyzer_available:

    st.error(
        "USB analyzer module could not be loaded."
    )

    st.code(
        analyzer_error
    )

    st.info(
        "Make sure modules/usb_analyzer.py exists "
        "in your GitHub repository."
    )

    st.stop()


# =====================================================
# CHECK EVIDENCE
# =====================================================

file_path = st.session_state.get(
    "evidence_path",
    ""
)

if not file_path:

    st.warning(
        "No evidence selected.\n\n"
        "Please load evidence from the Evidence Management page."
    )

    st.stop()


path = Path(file_path)

if not path.exists():

    st.error(
        "The selected evidence file no longer exists."
    )

    st.code(
        str(path)
    )

    st.stop()


st.success(
    "Evidence Loaded Successfully"
)

st.write("**Evidence:**")

st.code(
    str(path)
)

st.divider()


# =====================================================
# ANALYZE BUTTON
# =====================================================

if st.button(
    "Analyze USB Artifacts",
    use_container_width=True
):

    with st.spinner(
        "Analyzing USB artifacts..."
    ):

        try:

            # -------------------------------------------------
            # Call the analyzer module.
            #
            # The preferred function is:
            # usb_analyzer.analyze_usb(file_path)
            # -------------------------------------------------

            if hasattr(
                usb_analyzer,
                "analyze_usb"
            ):

                result = usb_analyzer.analyze_usb(
                    str(path)
                )

            else:

                st.error(
                    "The function 'analyze_usb' was not found "
                    "inside modules/usb_analyzer.py."
                )

                st.info(
                    "Your usb_analyzer.py must contain a function "
                    "named analyze_usb()."
                )

                st.stop()

        except Exception as e:

            st.error(
                "USB analysis failed."
            )

            st.exception(e)

            st.stop()


    # =================================================
    # NORMALIZE RESULT
    # =================================================

    if not isinstance(result, dict):

        result = {
            "risk_level": "LOW",
            "connected_devices": [],
            "findings": [
                str(result)
            ]
        }

    result.setdefault(
        "risk_level",
        "LOW"
    )

    result.setdefault(
        "connected_devices",
        []
    )

    result.setdefault(
        "findings",
        []
    )

    st.session_state.usb_result = result

    st.success(
        "USB Analysis Completed Successfully"
    )


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


# =====================================================
# SUMMARY
# =====================================================

st.subheader(
    "USB Analysis Summary"
)

col1, col2 = st.columns(2)

with col1:

    st.metric(
        "Risk Level",
        result.get(
            "risk_level",
            "LOW"
        )
    )

with col2:

    devices = result.get(
        "connected_devices",
        []
    )

    st.metric(
        "USB Devices",
        len(devices)
    )


st.divider()


# =====================================================
# CONNECTED USB DEVICES
# =====================================================

st.subheader(
    "Connected USB Devices"
)

devices = result.get(
    "connected_devices",
    []
)

if devices:

    for device in devices:

        st.info(
            str(device)
        )

else:

    st.success(
        "No USB devices detected."
    )


st.divider()


# =====================================================
# FINDINGS
# =====================================================

st.subheader(
    "Analysis Findings"
)

findings = result.get(
    "findings",
    []
)

if findings:

    for finding in findings:

        st.warning(
            str(finding)
        )

else:

    st.success(
        "No suspicious USB activity detected."
    )


st.divider()


# =====================================================
# NAVIGATION
# =====================================================

st.info(
    "USB analysis results are stored in the current session "
    "for use by other AFDS modules."
)

st.divider()

col1, col2 = st.columns(2)

with col1:

    st.page_link(
        "pages/1_Evidence.py",
        label="← Back to Evidence Management"
    )

with col2:

    st.page_link(
        "pages/6_File_Detection.py",
        label="Go to File Detection →"
    )


st.divider()

st.caption(
    "AFDS Version 1.0 | Digital Forensics Investigation Platform"
)
