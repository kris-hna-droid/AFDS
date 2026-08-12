import os

def analyze_disk_wiping(folder_path):

    suspicious_tools = [
        "sdelete.exe",
        "eraser.exe",
        "cipher.exe",
        "bleachbit.exe",
        "wipe.exe"
    ]

    detected = []
    findings = []
    risk = "LOW"

    for root, dirs, files in os.walk(folder_path):

        for file in files:

            if file.lower() in suspicious_tools:

                detected.append(file)

    if detected:

        risk = "HIGH"

        findings.append(
            f"{len(detected)} disk wiping tool(s) detected."
        )

    else:

        findings.append(
            "No disk wiping tools found."
        )

    return {

        "risk_level": risk,

        "wiping_tools": detected,

        "findings": findings

    }