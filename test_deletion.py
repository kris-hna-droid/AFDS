from modules.deletion_detector import scan_folder, compare_snapshots
from pathlib import Path
import json


test_folder = Path("evidence/test_folder")

# Create the test folder
test_folder.mkdir(parents=True, exist_ok=True)

# Create test files
for i in range(1, 6):
    file_path = test_folder / f"test_file_{i}.txt"
    file_path.write_text(f"Test evidence file {i}")

# Take the first snapshot
old_snapshot = scan_folder(test_folder)

print("OLD FILE COUNT:", old_snapshot["file_count"])

# Simulate a deletion for testing
(test_folder / "test_file_1.txt").unlink()
(test_folder / "test_file_2.txt").unlink()

# Take the second snapshot
new_snapshot = scan_folder(test_folder)

print("NEW FILE COUNT:", new_snapshot["file_count"])

# Compare the snapshots
result = compare_snapshots(old_snapshot, new_snapshot)

print("\n===== AFDS DELETION ANALYSIS =====")
print("Deleted Count:", result["deleted_count"])
print("Deleted Files:", result["deleted_files"])
print("Risk Level:", result["risk_level"])