import streamlit as st
import matplotlib.pyplot as plt
from pathlib import Path


# =====================================================
# PAGE CONFIGURATION
# =====================================================

st.set_page_config(
    page_title="Risk Dashboard",
    page_icon="📊",
    layout="wide"
)


# =====================================================
# LOAD CSS
# =====================================================

def load_css():

    # Get the AFDS project root directory
    project_root = Path(__file__).resolve().parent.parent

    css_file = project_root / "assets" / "style.css"

    if css_file.exists():

        with open(css_file, "r", encoding="utf-8") as f:

            st.markdown(
                f"<style>{f.read()}</style>",
                unsafe_allow_html=True
            )

    else:

        st.warning("CSS file not found: assets/style.css")


load_css()


# =====================================================
# SIDEBAR
# =====================================================

project_root = Path(__file__).resolve().parent.parent

logo_path = project_root / "assets" / "afds_logo.png"

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

st.title("Risk Dashboard")

st.caption(
    "Overall Anti-Forensics Risk Assessment"
)

st.divider()


# =====================================================
# GET RESULTS FROM SESSION STATE
# =====================================================

timestamp = st.session_state.get(
    "timestamp_result",
    {"risk_level": "LOW"}
)

event = st.session_state.get(
    "event_result",
    {"risk_level": "LOW"}
)

metadata = st.session_state.get(
    "metadata_result",
    {"risk_level": "LOW"}
)

usb = st.session_state.get(
    "usb_result",
    {"risk_level": "LOW"}
)

file_result = st.session_state.get(
    "file_result",
    {"risk_level": "LOW"}
)

browser = st.session_state.get(
    "browser_result",
    {"risk_level": "LOW"}
)

registry = st.session_state.get(
    "registry_result",
    {"risk_level": "LOW"}
)

encryption = st.session_state.get(
    "encryption_result",
    {"risk_level": "LOW"}
)

command = st.session_state.get(
    "command_result",
    {"risk_level": "LOW"}
)

disk = st.session_state.get(
    "disk_result",
    {"risk_level": "LOW"}
)


# =====================================================
# RISK VALUES
# =====================================================

risk_map = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3
}


# =====================================================
# MODULE RESULTS
# =====================================================

modules = {

    "Event Log":
        event.get("risk_level", "LOW"),

    "Timestamp":
        timestamp.get("risk_level", "LOW"),

    "Metadata":
        metadata.get("risk_level", "LOW"),

    "USB":
        usb.get("risk_level", "LOW"),

    "Files":
        file_result.get("risk_level", "LOW"),

    "Browser":
        browser.get("risk_level", "LOW"),

    "Registry":
        registry.get("risk_level", "LOW"),

    "Encryption":
        encryption.get("risk_level", "LOW"),

    "Command":
        command.get("risk_level", "LOW"),

    "Disk Wiping":
        disk.get("risk_level", "LOW")
}


# =====================================================
# CALCULATE RISK SCORE
# =====================================================

scores = []

for level in modules.values():

    # Protect against unexpected risk values
    level = str(level).upper()

    if level not in risk_map:
        level = "LOW"

    scores.append(
        risk_map[level]
    )


average = sum(scores) / len(scores)


# =====================================================
# DETERMINE OVERALL RISK
# =====================================================

if average >= 2.5:

    overall = "HIGH"

elif average >= 1.5:

    overall = "MEDIUM"

else:

    overall = "LOW"


# =====================================================
# OVERALL RISK DISPLAY
# =====================================================

with st.container(border=True):

    st.subheader("Overall Risk Assessment")

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "Overall Risk Level",
            overall
        )

    with col2:

        st.metric(
            "Average Risk Score",
            f"{average:.2f} / 3.00"
        )

    with col3:

        st.metric(
            "Modules Analysed",
            len(modules)
        )


st.divider()


# =====================================================
# MODULE RESULTS
# =====================================================

with st.container(border=True):

    st.subheader("Module Results")

    table = []

    for module, level in modules.items():

        table.append({

            "Module": module,

            "Risk Level": level

        })

    st.table(table)


st.divider()


# =====================================================
# RISK COMPARISON CHART
# =====================================================

with st.container(border=True):

    st.subheader("Risk Comparison")

    fig, ax = plt.subplots(
        figsize=(10, 5)
    )

    ax.bar(
        list(modules.keys()),
        scores
    )

    ax.set_ylabel(
        "Risk Level"
    )

    ax.set_ylim(
        0,
        3.5
    )

    ax.set_yticks(
        [1, 2, 3]
    )

    ax.set_yticklabels(
        [
            "LOW",
            "MEDIUM",
            "HIGH"
        ]
    )

    plt.xticks(
        rotation=25,
        ha="right"
    )

    plt.tight_layout()

    st.pyplot(
        fig,
        use_container_width=True
    )

    # Close the Matplotlib figure
    plt.close(fig)


st.divider()


# =====================================================
# INVESTIGATION SUMMARY
# =====================================================

with st.container(border=True):

    st.subheader("Investigation Summary")

    st.write(
        f"**Overall Risk Level:** {overall}"
    )

    st.write(
        f"**Average Risk Score:** {average:.2f} / 3.00"
    )

    st.write(
        f"**Modules Analysed:** {len(modules)}"
    )

    st.write(
        """
        This dashboard combines the results from all
        forensic analysis modules and provides an
        overall assessment of possible anti-forensics
        activity.
        """
    )


st.divider()


# =====================================================
# NAVIGATION HINTS
# =====================================================

with st.container(border=True):

    st.subheader("Next Steps")

    st.caption(
        "Review the assessment and generate the final forensic report."
    )

    col1, col2 = st.columns(2)

    with col1:

        st.page_link(
            "pages/13_Reports.py",
            label="Next: Generate Final Report"
        )

    with col2:

        st.page_link(
            "Home.py",
            label="Return to Home"
        )


st.divider()


# =====================================================
# FOOTER
# =====================================================

st.caption(
    "AFDS Version 1.0 | Digital Forensics Investigation Platform"
)