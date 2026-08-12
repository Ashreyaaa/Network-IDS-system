import sqlite3
import os

DATABASE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "ids.db"
)


def initialize_database():

    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT,

            alert_type TEXT,

            source_ip TEXT,

            ports TEXT,

            severity TEXT

        )
    """)

    connection.commit()
    connection.close()


def save_alert(timestamp, alert_type, source_ip, ports, severity):

    connection = sqlite3.connect(DATABASE_FILE)
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO alerts
        (
            timestamp,
            alert_type,
            source_ip,
            ports,
            severity
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        timestamp,
        alert_type,
        source_ip,
        ports,
        severity
    ))

    connection.commit()
    connection.close()