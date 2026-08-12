import os
import json
from datetime import datetime


def generate_report(timestamp_result, event_result, deletion_result, hash_result, risk_result):

    os.makedirs("reports", exist_ok=True)

    report_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    report_file = os.path.join(
        "reports",
        f"AFDS_Report_{report_time}.json"
    )

    report = {
        "case_name": "AFDS-CASE-001",
        "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

        "timestamp_analysis": timestamp_result,

        "event_log_analysis": event_result,

        "evidence_folder_analysis": deletion_result,

        "hash_analysis": hash_result,

        "overall_risk": risk_result
    }

    with open(report_file, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, default=str)

    return report_file