from modules.event_log_detector import analyze_event_log


event_log_file = "evidence/test_folder/test_event_log.txt"

result = analyze_event_log(event_log_file)


print("\n===== AFDS EVENT LOG ANALYSIS =====")


if result.get("status") == "ERROR":

    print("Error:", result["message"])

else:

    print("File:", result["file"])
    print("Risk Level:", result["risk_level"])
    print("Findings:")

    if result["findings"]:

        for finding in result["findings"]:
            print("-", finding)

    else:

        print("- No suspicious events detected.")