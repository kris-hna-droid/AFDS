import streamlit as st
from pathlib import Path
from datetime import datetime
import json
import hashlib


# =========================================================
# AFDS - ANTI-FORENSICS DETECTION SUITE
# =========================================================

st.set_page_config(
    page_title="AFDS | Digital Forensics",
    page_icon="🔍",
    layout="wide"
)


# =========================================================
# SAFE MODULE IMPORTS
# =========================================================

try:
    from modules.timestamp_analyzer import analyze_timestamps
except ImportError:
    analyze_timestamps = None

try:
    from modules.event_log_detector import analyze_event_log
except ImportError:
    analyze_event_log = None

try:
    from modules.hash_analyzer import analyze_hash
except ImportError:
    analyze_hash = None

try:
    from modules.deletion_detector import analyze_folder
except ImportError:
    analyze_folder = None


# =========================================================
# PAGE STYLE
# =========================================================

st.markdown("""
<style>

.stApp {
    background-color: #f5f7fb;
}

.title {
    font-size: 42px;
    font-weight: 800;
    color: #172554;
}

.subtitle {
    font-size: 18px;
    color: #475569;
}

.card {
    background-color: white;
    padding: 22px;
    border-radius: 15px;
    box-shadow: 0px 4px 15px rgba(0,0,0,0.08);
    margin-bottom: 20px;
}

.section-title {
    font-size: 25px;
    font-weight: 700;
    color: #1e3a8a;
    margin-top: 20px;
}

</style>
""", unsafe_allow_html=True)


# =========================================================
# HEADER
# =========================================================

st.markdown(
    '<div class="title">🔍 Anti-Forensics Detection Suite</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">Digital Forensics Analysis Dashboard</div>',
    unsafe_allow_html=True
)

st.divider()


# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.header("📁 Evidence Selection")

evidence_path = st.sidebar.text_input(
    "Enter evidence file path",
    value="evidence/test_folder/test_event_log.txt"
)

analyze_button = st.sidebar.button(
    "🚀 Analyze Evidence"
)


# =========================================================
# DEFAULT RESULTS
# =========================================================

timestamp_result = {
    "risk_level": "LOW",
    "findings": [],
    "created": "Not available",
    "modified": "Not available",
    "accessed": "Not available"
}

event_result = {
    "risk_level": "LOW",
    "findings": []
}

hash_result = {
    "sha256": "Not calculated"
}

deletion_result = {
    "risk_level": "LOW",
    "findings": []
}

overall_score = 0.0
overall_level = "LOW"
analysis_time = None


# =========================================================
# ANALYSIS
# =========================================================

if analyze_button:

    file_path = Path(evidence_path)

    if not file_path.exists():

        st.error(f"❌ Evidence file not found: {file_path}")

    else:

        analysis_time = datetime.now()

        st.success(f"✅ Evidence found: {file_path}")

        # -------------------------------------------------
        # TIMESTAMP ANALYSIS
        # -------------------------------------------------

        if analyze_timestamps:

            try:

                timestamp_result = analyze_timestamps(file_path)

                if timestamp_result is None:
                    timestamp_result = {}

                timestamp_result.setdefault(
                    "risk_level",
                    "LOW"
                )

                timestamp_result.setdefault(
                    "findings",
                    []
                )

                timestamp_result.setdefault(
                    "created",
                    "Not available"
                )

                timestamp_result.setdefault(
                    "modified",
                    "Not available"
                )

                timestamp_result.setdefault(
                    "accessed",
                    "Not available"
                )

            except Exception as e:

                timestamp_result = {
                    "risk_level": "LOW",
                    "findings": [
                        f"Timestamp analysis error: {str(e)}"
                    ],
                    "created": "Not available",
                    "modified": "Not available",
                    "accessed": "Not available"
                }


        # -------------------------------------------------
        # EVENT LOG ANALYSIS
        # -------------------------------------------------

        if analyze_event_log:

            try:

                event_result = analyze_event_log(
                    str(file_path)
                )

                if event_result is None:
                    event_result = {}

                event_result.setdefault(
                    "risk_level",
                    "LOW"
                )

                event_result.setdefault(
                    "findings",
                    []
                )

            except Exception as e:

                event_result = {
                    "risk_level": "LOW",
                    "findings": [
                        f"Event log analysis error: {str(e)}"
                    ]
                }


        # -------------------------------------------------
        # HASH ANALYSIS
        # -------------------------------------------------

        if analyze_hash:

            try:

                hash_result = analyze_hash(
                    str(file_path)
                )

                if hash_result is None:
                    hash_result = {
                        "sha256": "Hash not available"
                    }

            except Exception as e:

                hash_result = {
                    "sha256": f"Hash error: {str(e)}"
                }


        # -------------------------------------------------
        # DELETION ANALYSIS
        # -------------------------------------------------

        if analyze_folder:

            try:

                deletion_result = analyze_folder(
                    str(file_path)
                )

                if deletion_result is None:
                    deletion_result = {}

                deletion_result.setdefault(
                    "risk_level",
                    "LOW"
                )

                deletion_result.setdefault(
                    "findings",
                    []
                )

            except Exception as e:

                deletion_result = {
                    "risk_level": "LOW",
                    "findings": [
                        f"Deletion analysis error: {str(e)}"
                    ]
                }


        # =================================================
        # RISK CALCULATION
        # =================================================

        risk_values = {
            "LOW": 0,
            "MEDIUM": 50,
            "HIGH": 100
        }

        risk_levels = [

            timestamp_result.get(
                "risk_level",
                "LOW"
            ).upper(),

            event_result.get(
                "risk_level",
                "LOW"
            ).upper(),

            deletion_result.get(
                "risk_level",
                "LOW"
            ).upper()

        ]

        risk_scores = [

            risk_values.get(
                level,
                0
            )

            for level in risk_levels

        ]

        if risk_scores:

            overall_score = (
                sum(risk_scores)
                /
                len(risk_scores)
            )

        if overall_score >= 70:

            overall_level = "HIGH"

        elif overall_score >= 40:

            overall_level = "MEDIUM"

        else:

            overall_level = "LOW"


        # =================================================
        # CREATE REPORTS
        # =================================================

        reports_folder = Path("reports")

        reports_folder.mkdir(
            exist_ok=True
        )

        report_time = datetime.now()

        report_data = {

            "AFDS Report": {

                "evidence_file": str(
                    file_path.absolute()
                ),

                "analysis_time": report_time.strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),

                "overall_risk_score": round(
                    overall_score,
                    2
                ),

                "overall_risk_level": overall_level

            },

            "timestamp_analysis": timestamp_result,

            "event_log_analysis": event_result,

            "hash_analysis": hash_result,

            "deletion_analysis": deletion_result

        }


        # -------------------------------------------------
        # JSON REPORT
        # -------------------------------------------------

        json_report_path = (
            reports_folder
            /
            f"afds_report_{report_time.strftime('%Y%m%d_%H%M%S')}.json"
        )

        with open(
            json_report_path,
            "w",
            encoding="utf-8"
        ) as json_file:

            json.dump(
                report_data,
                json_file,
                indent=4,
                default=str
            )


        # -------------------------------------------------
        # TXT REPORT
        # -------------------------------------------------

        txt_report_path = (
            reports_folder
            /
            f"afds_report_{report_time.strftime('%Y%m%d_%H%M%S')}.txt"
        )

        with open(
            txt_report_path,
            "w",
            encoding="utf-8"
        ) as report_file:

            report_file.write(
                "========================================\n"
            )

            report_file.write(
                "       AFDS FORENSIC ANALYSIS REPORT\n"
            )

            report_file.write(
                "========================================\n\n"
            )

            report_file.write(
                f"Evidence File:\n"
                f"{file_path.absolute()}\n\n"
            )

            report_file.write(
                f"Analysis Time:\n"
                f"{report_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            )

            report_file.write(
                "----------------------------------------\n"
            )

            report_file.write(
                "OVERALL RISK ASSESSMENT\n"
            )

            report_file.write(
                "----------------------------------------\n"
            )

            report_file.write(
                f"Risk Score: {overall_score:.2f}\n"
            )

            report_file.write(
                f"Risk Level: {overall_level}\n\n"
            )


            report_file.write(
                "----------------------------------------\n"
            )

            report_file.write(
                "TIMESTAMP ANALYSIS\n"
            )

            report_file.write(
                "----------------------------------------\n"
            )

            report_file.write(
                f"Risk Level: "
                f"{timestamp_result.get('risk_level')}\n"
            )

            report_file.write(
                f"Created: "
                f"{timestamp_result.get('created')}\n"
            )

            report_file.write(
                f"Modified: "
                f"{timestamp_result.get('modified')}\n"
            )

            report_file.write(
                f"Accessed: "
                f"{timestamp_result.get('accessed')}\n"
            )

            report_file.write(
                "Findings:\n"
            )

            for finding in timestamp_result.get(
                "findings",
                []
            ):

                report_file.write(
                    f"- {finding}\n"
                )

            report_file.write("\n")


            report_file.write(
                "----------------------------------------\n"
            )

            report_file.write(
                "EVENT LOG ANALYSIS\n"
            )

            report_file.write(
                "----------------------------------------\n"
            )

            report_file.write(
                f"Risk Level: "
                f"{event_result.get('risk_level')}\n"
            )

            report_file.write(
                "Findings:\n"
            )

            for finding in event_result.get(
                "findings",
                []
            ):

                report_file.write(
                    f"- {finding}\n"
                )

            report_file.write("\n")


            report_file.write(
                "----------------------------------------\n"
            )

            report_file.write(
                "HASH ANALYSIS\n"
            )

            report_file.write(
                "----------------------------------------\n"
            )

            report_file.write(
                f"SHA-256: "
                f"{hash_result.get('sha256')}\n\n"
            )


            report_file.write(
                "----------------------------------------\n"
            )

            report_file.write(
                "DELETION / EVIDENCE ANALYSIS\n"
            )

            report_file.write(
                "----------------------------------------\n"
            )

            report_file.write(
                f"Risk Level: "
                f"{deletion_result.get('risk_level')}\n"
            )

            report_file.write(
                "Findings:\n"
            )

            for finding in deletion_result.get(
                "findings",
                []
            ):

                report_file.write(
                    f"- {finding}\n"
                )

            report_file.write("\n")

            report_file.write(
                "========================================\n"
            )

            report_file.write(
                "              END OF REPORT\n"
            )

            report_file.write(
                "========================================\n"
            )


        st.success(
            "✅ Analysis completed and reports generated!"
        )

        st.info(
            f"📁 Reports saved in: {reports_folder.absolute()}"
        )

        # -------------------------------------------------
        # DOWNLOAD REPORT
        # -------------------------------------------------

        with open(
            txt_report_path,
            "rb"
        ) as report_file:

            st.download_button(
                label="📥 Download TXT Report",
                data=report_file,
                file_name=txt_report_path.name,
                mime="text/plain"
            )


        with open(
            json_report_path,
            "rb"
        ) as json_file:

            st.download_button(
                label="📥 Download JSON Report",
                data=json_file,
                file_name=json_report_path.name,
                mime="application/json"
            )


# =========================================================
# DASHBOARD
# =========================================================

st.markdown(
    '<div class="section-title">'
    '📊 Overall Risk Assessment'
    '</div>',
    unsafe_allow_html=True
)

col1, col2 = st.columns(2)

with col1:

    st.metric(
        "Risk Score",
        f"{overall_score:.1f}"
    )

with col2:

    st.metric(
        "Overall Risk Level",
        overall_level
    )


# =========================================================
# TIMESTAMP ANALYSIS
# =========================================================

st.markdown(
    '<div class="section-title">'
    '🕒 Timestamp Analysis'
    '</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="card">',
    unsafe_allow_html=True
)

st.write(
    "Risk Level:",
    timestamp_result.get(
        "risk_level",
        "LOW"
    )
)

st.write(
    "📅 Created:",
    timestamp_result.get(
        "created",
        "Not available"
    )
)

st.write(
    "✏️ Modified:",
    timestamp_result.get(
        "modified",
        "Not available"
    )
)

st.write(
    "👁️ Accessed:",
    timestamp_result.get(
        "accessed",
        "Not available"
    )
)

timestamp_findings = timestamp_result.get(
    "findings",
    []
)

if timestamp_findings:

    for finding in timestamp_findings:

        st.warning(finding)

else:

    st.success(
        "No suspicious timestamp findings detected."
    )

st.markdown(
    '</div>',
    unsafe_allow_html=True
)


# =========================================================
# EVENT LOG ANALYSIS
# =========================================================

st.markdown(
    '<div class="section-title">'
    '📜 Event Log Analysis'
    '</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="card">',
    unsafe_allow_html=True
)

st.write(
    "Risk Level:",
    event_result.get(
        "risk_level",
        "LOW"
    )
)

event_findings = event_result.get(
    "findings",
    []
)

if event_findings:

    for finding in event_findings:

        st.warning(finding)

else:

    st.success(
        "No suspicious event log findings detected."
    )

st.markdown(
    '</div>',
    unsafe_allow_html=True
)


# =========================================================
# HASH ANALYSIS
# =========================================================

st.markdown(
    '<div class="section-title">'
    '🔐 File Hash Analysis'
    '</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="card">',
    unsafe_allow_html=True
)

st.write(
    "SHA-256 Hash:"
)

st.code(
    hash_result.get(
        "sha256",
        "Hash not available"
    )
)

st.markdown(
    '</div>',
    unsafe_allow_html=True
)


# =========================================================
# DELETION ANALYSIS
# =========================================================

st.markdown(
    '<div class="section-title">'
    '📁 Evidence Folder Analysis'
    '</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="card">',
    unsafe_allow_html=True
)

st.write(
    "Risk Level:",
    deletion_result.get(
        "risk_level",
        "LOW"
    )
)

deletion_findings = deletion_result.get(
    "findings",
    []
)

if deletion_findings:

    for finding in deletion_findings:

        st.warning(finding)

else:

    st.success(
        "No suspicious deletion findings detected."
    )

st.markdown(
    '</div>',
    unsafe_allow_html=True
)


# =========================================================
# FOOTER
# =========================================================

st.divider()

st.caption(
    f"Analysis completed: "
    f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
)