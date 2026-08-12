from modules.timestamp_analyzer import analyze_file
from modules.event_log_detector import analyze_event_log
from modules.deletion_detector import scan_folder
from modules.risk_engine import calculate_overall_risk


print("\n================================")
print("       AFDS ANALYSIS SUITE")
print("================================")


# 1. Timestamp Analysis
timestamp_result = analyze_file(
    "test_file.txt"
)


# 2. Event Log Analysis
event_log_result = analyze_event_log(
    "evidence/test_folder/test_event_log.txt"
)


# 3. Deletion Analysis
deletion_result = scan_folder(
    "evidence/test_folder"
)


# Collect results for the Risk Engine
analysis_results = []


if timestamp_result.get("status") != "ERROR":
    analysis_results.append(timestamp_result)


if event_log_result.get("status") != "ERROR":
    analysis_results.append(event_log_result)


# 4. Calculate Overall Risk
overall_result = calculate_overall_risk(
    analysis_results
)


# ==============================
# TIMESTAMP ANALYSIS
# ==============================

print("\n===== TIMESTAMP ANALYSIS =====")

if timestamp_result.get("status") == "ERROR":

    print("Error:", timestamp_result.get("message"))

else:

    print("File:", timestamp_result.get("file"))
    print("Created:", timestamp_result.get("created"))
    print("Modified:", timestamp_result.get("modified"))
    print("Accessed:", timestamp_result.get("accessed"))
    print("Risk Level:", timestamp_result.get("risk_level"))
    print("Findings:", timestamp_result.get("findings"))


# ==============================
# EVENT LOG ANALYSIS
# ==============================

print("\n===== EVENT LOG ANALYSIS =====")

if event_log_result.get("status") == "ERROR":

    print("Error:", event_log_result.get("message"))

else:

    print("File:", event_log_result.get("file"))
    print("Risk Level:", event_log_result.get("risk_level"))
    print("Findings:", event_log_result.get("findings"))


# ==============================
# DELETION ANALYSIS
# ==============================

print("\n===== DELETION ANALYSIS =====")

if deletion_result.get("status") == "ERROR":

    print("Error:", deletion_result.get("message"))

else:

    print("Files Scanned:", deletion_result.get("file_count"))
    print("Status: Folder snapshot created")


# ==============================
# OVERALL RISK
# ==============================

print("\n===== OVERALL AFDS RISK =====")

print("Risk Score:", overall_result.get("score"))
print("Overall Risk Level:", overall_result.get("risk_level"))