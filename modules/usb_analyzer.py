from pathlib import Path


def analyze_usb(file_path):
    """
    Analyze USB artifact evidence.

    Parameters
    ----------
    file_path : str
        Path to a USB artifact file or evidence folder.

    Returns
    -------
    dict
        Dictionary containing risk level, connected devices,
        and analysis findings.
    """

    # --------------------------------------------------
    # INITIAL RESULT
    # --------------------------------------------------

    result = {
        "risk_level": "LOW",
        "connected_devices": [],
        "findings": []
    }

    # --------------------------------------------------
    # VALIDATE PATH
    # --------------------------------------------------

    if not file_path:
        raise ValueError("No evidence path was provided.")

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Evidence path does not exist: {path}"
        )

    # --------------------------------------------------
    # GET EVIDENCE FILES
    # --------------------------------------------------

    if path.is_file():

        files = [path]

    elif path.is_dir():

        files = [
            item
            for item in path.rglob("*")
            if item.is_file()
        ]

    else:

        raise ValueError(
            "The selected evidence path is invalid."
        )

    # --------------------------------------------------
    # CHECK FOR EMPTY EVIDENCE
    # --------------------------------------------------

    if not files:

        result["findings"].append(
            "No evidence files were found."
        )

        return result

    # --------------------------------------------------
    # USB KEYWORDS
    # --------------------------------------------------

    usb_keywords = [
        "usb",
        "usb device",
        "usb storage",
        "usb mass storage",
        "removable",
        "removable storage",
        "flash drive",
        "mass storage",
        "vid_",
        "pid_",
        "device connected",
        "storage device"
    ]

    # --------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # --------------------------------------------------

    suspicious_keywords = [
        "unknown device",
        "unknown usb",
        "unauthorized",
        "suspicious",
        "malicious",
        "blocked",
        "failed",
        "error"
    ]

    # --------------------------------------------------
    # ANALYZE FILES
    # --------------------------------------------------

    for evidence_file in files:

        try:

            text = evidence_file.read_text(
                encoding="utf-8",
                errors="ignore"
            )

        except Exception:

            # Ignore files that cannot be read as text
            continue

        lines = text.splitlines()

        for line in lines:

            line = line.strip()

            if not line:
                continue

            lower_line = line.lower()

            # ------------------------------------------
            # USB DEVICE DETECTION
            # ------------------------------------------

            if any(
                keyword in lower_line
                for keyword in usb_keywords
            ):

                device = (
                    f"{evidence_file.name}: {line}"
                )

                if device not in result[
                    "connected_devices"
                ]:

                    result[
                        "connected_devices"
                    ].append(device)

            # ------------------------------------------
            # SUSPICIOUS ACTIVITY
            # ------------------------------------------

            if any(
                keyword in lower_line
                for keyword in suspicious_keywords
            ):

                finding = (
                    f"{evidence_file.name}: {line}"
                )

                if finding not in result["findings"]:

                    result["findings"].append(
                        finding
                    )

    # --------------------------------------------------
    # DETERMINE RISK LEVEL
    # --------------------------------------------------

    if result["findings"]:

        result["risk_level"] = "HIGH"

    elif len(
        result["connected_devices"]
    ) >= 5:

        result["risk_level"] = "MEDIUM"

    elif result["connected_devices"]:

        result["risk_level"] = "LOW"

    else:

        result["risk_level"] = "LOW"

    # --------------------------------------------------
    # NO USB DEVICES FOUND
    # --------------------------------------------------

    if not result["connected_devices"]:

        result["findings"].append(
            "No USB device entries were detected "
            "in the supplied evidence."
        )

    return result
