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
    from modules.command_history_analyzer import analyze_command_history
except ImportError:
    analyze_command_history = None


st.set_page_config(
    page_title="Command History Analysis",
    page_icon="🖥️",
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

st.title("Command History Analysis")

st.write(
    "Analyze command history to identify suspicious or anti-forensics related commands."
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
    "Analyze Command History",
    use_container_width=True
):

    if analyze_command_history is None:

        st.error("modules/command_history_analyzer.py not found.")

    else:

        with st.spinner("Analyzing command history..."):

            try:

                result = analyze_command_history(str(path))

            except Exception as e:

                result = {
                    "risk_level": "LOW",
                    "total_commands": 0,
                    "suspicious_commands": [],
                    "findings": [str(e)]
                }

        st.session_state.command_result = result

        st.success("Command History Analysis Completed")

st.divider()

# =====================================================
# DISPLAY RESULTS
# =====================================================

result = st.session_state.get(
    "command_result",
    {
        "risk_level": "LOW",
        "total_commands": 0,
        "suspicious_commands": [],
        "findings": []
    }
)

col1, col2, col3 = st.columns(3)

with col1:

    st.metric(
        "Risk Level",
        result.get("risk_level", "LOW")
    )

with col2:

    st.metric(
        "Total Commands",
        result.get("total_commands", 0)
    )

with col3:

    st.metric(
        "Suspicious Commands",
        len(result.get("suspicious_commands", []))
    )

st.divider()

# =====================================================
# SUSPICIOUS COMMANDS
# =====================================================

st.subheader("Suspicious Commands")

commands = result.get("suspicious_commands", [])

if commands:

    for command in commands:

        st.code(command)

else:

    st.success(
        "No suspicious commands detected."
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
        "No suspicious command history detected."
    )

st.divider()

st.info(
    "Command history analysis has been stored for the Risk Dashboard and Reports pages."
)

st.divider()

col1, col2 = st.columns(2)

with col1:
    st.page_link(
        "pages/9_Command_History.py",
        label="Start Command History Analysis"
    )

with col2:
    st.page_link(
        "pages/10_Registry.py",
        label="Go to Registry Analysis"
    )

st.divider()

st.caption(
    "AFDS Version 1.0 | Digital Forensics Investigation Platform"
)