from modules.timestamp_analyzer import analyze_file

file_to_analyze = "test_file.txt"

result = analyze_file(file_to_analyze)

print("\n===== AFDS TIMESTAMP ANALYSIS =====")

for key, value in result.items():
    print(f"{key}: {value}")