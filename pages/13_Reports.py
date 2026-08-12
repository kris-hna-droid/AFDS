import streamlit as st
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from pathlib import Path
from datetime import datetime
from xml.sax.saxutils import escape


# =====================================================
# PAGE CONFIG
# =====================================================

st.set_page_config(
    page_title="Reports",
    page_icon="AFDS",
    layout="wide"
)


# =====================================================
# LOAD CSS
# =====================================================

def load_css():

    css_file = Path("assets/style.css")

    if css_file.exists():

        with open(css_file, "r", encoding="utf-8") as f:

            st.markdown(
                f"<style>{f.read()}</style>",
                unsafe_allow_html=True
            )


load_css()


# =====================================================
# SIDEBAR
# =====================================================

logo_path = Path("assets/afds_logo.png")

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

st.title("Forensic Report Generator")

st.caption(
    "Generate a complete PDF forensic investigation report "
    "from the available analysis results."
)

st.divider()


# =====================================================
# CASE INFORMATION
# =====================================================

with st.container(border=True):

    st.subheader("Case Information")

    examiner = st.text_input(
        "Examiner Name",
        key="examiner_name"
    )

    case_number = st.text_input(
        "Case Number",
        key="case_number"
    )

    description = st.text_area(
        "Case Description",
        key="case_description"
    )


st.divider()


# =====================================================
# REPORT FOLDER
# =====================================================

reports_folder = Path("reports")

reports_folder.mkdir(
    exist_ok=True
)


# =====================================================
# GET EVIDENCE PATH
# =====================================================
#
# Your Evidence page currently saves:
#
# st.session_state.evidence_path
#
# Some older analysis pages may use:
#
# st.session_state.file_path
#
# Therefore we check both.
# =====================================================

file_path = st.session_state.get(
    "file_path"
)

if not file_path:

    file_path = st.session_state.get(
        "evidence_path"
    )

if not file_path:

    file_path = "Not Selected"


# =====================================================
# GET ANALYSIS RESULTS
# =====================================================

timestamp = st.session_state.get(
    "timestamp_result",
    {}
)

event = st.session_state.get(
    "event_result",
    {}
)

metadata = st.session_state.get(
    "metadata_result",
    {}
)

usb = st.session_state.get(
    "usb_result",
    {}
)

file_result = st.session_state.get(
    "file_result",
    {}
)

browser = st.session_state.get(
    "browser_result",
    {}
)

encryption = st.session_state.get(
    "encryption_result",
    {}
)

command = st.session_state.get(
    "command_result",
    {}
)

registry = st.session_state.get(
    "registry_result",
    {}
)

disk = st.session_state.get(
    "disk_result",
    {}
)


# =====================================================
# CALCULATE OVERALL RISK
# =====================================================

risk_map = {

    "LOW": 1,

    "MEDIUM": 2,

    "HIGH": 3

}


levels = [

    event.get(
        "risk_level",
        "LOW"
    ).upper(),

    timestamp.get(
        "risk_level",
        "LOW"
    ).upper(),

    metadata.get(
        "risk_level",
        "LOW"
    ).upper(),

    usb.get(
        "risk_level",
        "LOW"
    ).upper(),

    file_result.get(
        "risk_level",
        "LOW"
    ).upper(),

    browser.get(
        "risk_level",
        "LOW"
    ).upper(),

    encryption.get(
        "risk_level",
        "LOW"
    ).upper(),

    command.get(
        "risk_level",
        "LOW"
    ).upper(),

    registry.get(
        "risk_level",
        "LOW"
    ).upper(),

    disk.get(
        "risk_level",
        "LOW"
    ).upper()

]


# Convert unknown values to LOW
numeric_levels = []

for level in levels:

    numeric_levels.append(
        risk_map.get(
            level,
            1
        )
    )


score = sum(numeric_levels) / len(numeric_levels)


if score >= 2.5:

    overall = "HIGH"

elif score >= 1.5:

    overall = "MEDIUM"

else:

    overall = "LOW"


# =====================================================
# SHOW CURRENT STATUS
# =====================================================

with st.container(border=True):

    st.subheader("Report Summary")

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "Overall Risk Score",
            f"{score:.2f}"
        )

    with col2:

        st.metric(
            "Overall Risk Level",
            overall
        )

    with col3:

        if file_path != "Not Selected":

            st.metric(
                "Evidence",
                "Selected"
            )

        else:

            st.metric(
                "Evidence",
                "Not Selected"
            )


st.divider()


# =====================================================
# GENERATE PDF
# =====================================================

if st.button(
    "Generate PDF Report",
    use_container_width=True
):

    now = datetime.now()

    pdf_report_path = (
        reports_folder
        /
        f"AFDS_Report_{now.strftime('%Y%m%d_%H%M%S')}.pdf"
    )


    # =================================================
    # CREATE PDF
    # =================================================

    doc = SimpleDocTemplate(
        str(pdf_report_path),
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )


    styles = getSampleStyleSheet()

    elements = []


    # =================================================
    # TITLE
    # =================================================

    elements.append(
        Paragraph(
            "AFDS FORENSIC ANALYSIS REPORT",
            styles["Title"]
        )
    )

    elements.append(
        Spacer(1, 20)
    )


    # =================================================
    # CASE INFORMATION
    # =================================================

    elements.append(
        Paragraph(
            "<b>CASE INFORMATION</b>",
            styles["Heading2"]
        )
    )

    elements.append(
        Paragraph(
            f"Case Number : {escape(str(case_number))}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"Examiner : {escape(str(examiner))}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"Description : {escape(str(description))}",
            styles["BodyText"]
        )
    )

    elements.append(
        Spacer(1, 15)
    )


    # =================================================
    # EVIDENCE INFORMATION
    # =================================================

    elements.append(
        Paragraph(
            "<b>EVIDENCE INFORMATION</b>",
            styles["Heading2"]
        )
    )

    elements.append(
        Paragraph(
            f"Evidence Path : {escape(str(file_path))}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"Report Generated : {now.strftime('%Y-%m-%d %H:%M:%S')}",
            styles["BodyText"]
        )
    )

    elements.append(
        Spacer(1, 15)
    )


    # =================================================
    # OVERALL RISK
    # =================================================

    elements.append(
        Paragraph(
            "<b>OVERALL RISK ASSESSMENT</b>",
            styles["Heading2"]
        )
    )

    elements.append(
        Paragraph(
            f"Overall Risk Score : {score:.2f}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"Overall Risk Level : {overall}",
            styles["BodyText"]
        )
    )

    elements.append(
        Spacer(1, 15)
    )


    # =================================================
    # HELPER FUNCTION FOR MODULES
    # =================================================

    def add_module(
        title,
        result
    ):

        elements.append(
            Paragraph(
                title,
                styles["Heading2"]
            )
        )

        risk = result.get(
            "risk_level",
            "LOW"
        )

        elements.append(
            Paragraph(
                f"Risk Level : {escape(str(risk))}",
                styles["BodyText"]
            )
        )


        findings = result.get(
            "findings",
            []
        )


        if findings:

            elements.append(
                Paragraph(
                    "<b>Findings:</b>",
                    styles["BodyText"]
                )
            )

            for finding in findings:

                elements.append(
                    Paragraph(
                        f"• {escape(str(finding))}",
                        styles["BodyText"]
                    )
                )

        else:

            elements.append(
                Paragraph(
                    "Findings : No findings recorded.",
                    styles["BodyText"]
                )
            )


        elements.append(
            Spacer(1, 10)
        )


    # =================================================
    # ANALYSIS MODULES
    # =================================================

    add_module(
        "1. TIMESTAMP ANALYSIS",
        timestamp
    )


    add_module(
        "2. EVENT LOG ANALYSIS",
        event
    )


    add_module(
        "3. METADATA ANALYSIS",
        metadata
    )


    add_module(
        "4. USB ARTIFACT ANALYSIS",
        usb
    )


    add_module(
        "5. FILE DETECTION ANALYSIS",
        file_result
    )


    add_module(
        "6. BROWSER HISTORY ANALYSIS",
        browser
    )


    add_module(
        "7. ENCRYPTION ANALYSIS",
        encryption
    )


    add_module(
        "8. COMMAND HISTORY ANALYSIS",
        command
    )


    add_module(
        "9. REGISTRY ANALYSIS",
        registry
    )


    add_module(
        "10. DISK WIPING ANALYSIS",
        disk
    )


    # =================================================
    # FOOTER INFORMATION
    # =================================================

    elements.append(
        Spacer(1, 15)
    )

    elements.append(
        Paragraph(
            "AFDS Version 1.0 | Digital Forensics Investigation Platform",
            styles["BodyText"]
        )
    )


    # =================================================
    # BUILD PDF
    # =================================================

    doc.build(
        elements
    )


    # =================================================
    # SUCCESS MESSAGE
    # =================================================

    st.success(
        "PDF forensic report generated successfully."
    )


    # =================================================
    # DOWNLOAD PDF
    # =================================================

    with open(
        pdf_report_path,
        "rb"
    ) as pdf_file:

        st.download_button(

            label="Download PDF Report",

            data=pdf_file,

            file_name=pdf_report_path.name,

            mime="application/pdf",

            use_container_width=True

        )


st.divider()


# =====================================================
# NAVIGATION
# =====================================================

col1, col2 = st.columns(2)


with col1:

    st.page_link(
        "pages/12_Risk_Dashboard.py",
        label="Back to Risk Dashboard"
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