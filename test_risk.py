from modules.risk_engine import calculate_overall_risk


results = [
    {
        "risk_level": "MEDIUM"
    },
    {
        "risk_level": "HIGH"
    }
]


overall_result = calculate_overall_risk(results)


print("\n===== AFDS OVERALL RISK ANALYSIS =====")
print("Risk Score:", overall_result["score"])
print("Overall Risk Level:", overall_result["risk_level"])