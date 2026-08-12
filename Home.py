import streamlit as st
from pathlib import Path
from PIL import Image

logo_path = Path("assets/afds_logo.png")

if logo_path.exists():
    logo = Image.open(logo_path)

    st.sidebar.image(logo, width=100)

st.image(
    logo,
    width=120
)


st.set_page_config(
    page_title="AFDS",
    page_icon="🛡️",
    layout="wide"
)

# =====================================================
# CUSTOM CSS
# =====================================================

st.markdown("""
<style>

.main{
    background:#f4f6f9;
}

.hero{

background:#0B1F3A;

padding:40px;

border-radius:15px;

color:white;

}

.hero h1{

font-size:44px;

font-weight:bold;

}

.hero p{

font-size:18px;

color:#d8e3f2;

}

.card{

background:white;

padding:20px;

border-radius:12px;

box-shadow:0 3px 8px rgba(0,0,0,.12);

text-align:center;

height:170px;

}

.card h3{

color:#0B1F3A;

}

.footer{

text-align:center;

color:gray;

margin-top:40px;

}

</style>
""", unsafe_allow_html=True)

# =====================================================
# HERO
# =====================================================

st.markdown("""

<div class="hero">

<h1>Anti-Forensics Detection Suite</h1>

<p>

Professional Digital Forensics Platform for Detecting
Anti-Forensics Techniques in Digital Evidence.

</p>

</div>

""", unsafe_allow_html=True)

st.write("")

# =====================================================
# MODULE CARDS
# =====================================================

st.subheader("Available Investigation Modules")

col1,col2,col3=st.columns(3)

with col1:

    st.markdown("""

<div class="card">

<h3>Evidence Management</h3>

Select evidence for forensic investigation.

</div>

""",unsafe_allow_html=True)

    st.page_link("pages/1_Evidence.py",
                 label="Open")

with col2:

    st.markdown("""

<div class="card">

<h3>Event Log Analysis</h3>

Detect cleared or modified logs.

</div>

""",unsafe_allow_html=True)

    st.page_link("pages/2_Event_Log.py",
                 label="Open")

with col3:

    st.markdown("""

<div class="card">

<h3>Timestamp Analysis</h3>

Detect timestamp manipulation.

</div>

""",unsafe_allow_html=True)

    st.page_link("pages/3_Timestamp.py",
                 label="Open")

# =====================================================
# SECOND ROW
# =====================================================

col1,col2,col3=st.columns(3)

with col1:

    st.markdown("""

<div class="card">

<h3>Metadata Analysis</h3>

Inspect file metadata.

</div>

""",unsafe_allow_html=True)

    st.page_link("pages/4_Metadata.py",
                 label="Open")

with col2:

    st.markdown("""

<div class="card">

<h3>USB Analysis</h3>

Detect removable storage artifacts.

</div>

""",unsafe_allow_html=True)

    st.page_link("pages/5_USB_Artifacts.py",
                 label="Open")

with col3:

    st.markdown("""

<div class="card">

<h3>File Detection</h3>

Hidden, deleted and suspicious files.

</div>

""",unsafe_allow_html=True)

    st.page_link("pages/6_File_Detection.py",
                 label="Open")

# =====================================================
# THIRD ROW
# =====================================================

col1,col2,col3,col4=st.columns(4)

modules = [
    ("Browser History","pages/7_Browser_History.py"),
    ("Encryption","pages/8_Encryption.py"),
    ("Command History","pages/9_Command_History.py"),
    ("Registry","pages/10_Registry.py")
]

for col,(name,page) in zip([col1,col2,col3,col4],modules):

    with col:

        st.markdown(f"""

<div class="card">

<h3>{name}</h3>

</div>

""",unsafe_allow_html=True)

        st.page_link(page,label="Open")

# =====================================================
# FOURTH ROW
# =====================================================

col1,col2,col3=st.columns(3)

with col1:

    st.markdown("""

<div class="card">

<h3>Disk Wiping</h3>

Detect secure deletion tools.

</div>

""",unsafe_allow_html=True)

    st.page_link("pages/11_Disk_Wiping.py",
                 label="Open")

with col2:

    st.markdown("""

<div class="card">

<h3>Risk Dashboard</h3>

Combined forensic assessment.

</div>

""",unsafe_allow_html=True)

    st.page_link("pages/12_Risk_Dashboard.py",
                 label="Open")

with col3:

    st.markdown("""

<div class="card">

<h3>Reports</h3>

Generate forensic reports.

</div>

""",unsafe_allow_html=True)

    st.page_link("pages/13_Reports.py",
                 label="Open")

# =====================================================
# WORKFLOW
# =====================================================

st.divider()

st.subheader("Investigation Workflow")

st.write("""
1. Load Evidence

2. Run Required Analysis Modules

3. Review Risk Dashboard

4. Generate Investigation Report
""")

st.divider()

st.subheader("Platform Information")

c1,c2,c3,c4=st.columns(4)

c1.metric("Modules","10")
c2.metric("Reports","3")
c3.metric("Dashboard","1")
c4.metric("Version","1.0")

st.divider()

st.markdown("""

<div class="footer">

<b>Anti-Forensics Detection Suite (AFDS)</b><br>

Digital Forensics Investigation Platform

</div>

""",unsafe_allow_html=True)