import sqlite3
from pathlib import Path
from datetime import datetime


DATABASE_PATH = Path("database/afds.db")


def create_database():

    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigations (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            case_name TEXT,

            evidence_file TEXT,

            sha256_hash TEXT,

            risk_level TEXT,

            findings TEXT,

            analysis_time TEXT

        )
    """)

    connection.commit()

    connection.close()


def save_investigation(
    case_name,
    evidence_file,
    sha256_hash,
    risk_level,
    findings
):

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO investigations (
            case_name,
            evidence_file,
            sha256_hash,
            risk_level,
            findings,
            analysis_time
        )

        VALUES (?, ?, ?, ?, ?, ?)
    """, (

        case_name,
        evidence_file,
        sha256_hash,
        risk_level,
        str(findings),
        datetime.now().isoformat()

    ))

    connection.commit()

    connection.close()