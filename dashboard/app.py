from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for
)

import sqlite3
import os


# ============================================================
# FLASK
# ============================================================

app = Flask(__name__)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATABASE_FILE = os.path.join(
    BASE_DIR,
    "storage",
    "ids.db"
)

STATUS_FILE = os.path.join(
    BASE_DIR,
    "monitoring.status"
)


# ============================================================
# MONITORING STATUS
# ============================================================

def get_monitoring_status():

    try:

        with open(
            STATUS_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return file.read().strip()

    except FileNotFoundError:

        return "STOPPED"


def set_monitoring_status(status):

    with open(
        STATUS_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(status)


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():

    connection = sqlite3.connect(
        DATABASE_FILE
    )

    connection.row_factory = sqlite3.Row

    return connection


# ============================================================
# GET ALERTS
# ============================================================

def get_alerts():

    connection = get_connection()

    cursor = connection.cursor()

    severity = request.args.get(
        "severity",
        ""
    )

    attack_type = request.args.get(
        "attack_type",
        ""
    )

    source_ip = request.args.get(
        "source_ip",
        ""
    )


    query = """
        SELECT
            id,
            timestamp,
            alert_type,
            source_ip,
            ports,
            severity
        FROM alerts
        WHERE 1=1
    """

    parameters = []


    # --------------------------------------------------------
    # SEVERITY FILTER
    # --------------------------------------------------------

    if severity:

        query += """
            AND severity = ?
        """

        parameters.append(
            severity
        )


    # --------------------------------------------------------
    # ATTACK TYPE FILTER
    # --------------------------------------------------------

    if attack_type:

        query += """
            AND alert_type LIKE ?
        """

        parameters.append(
            f"%{attack_type}%"
        )


    # --------------------------------------------------------
    # SOURCE IP FILTER
    # --------------------------------------------------------

    if source_ip:

        query += """
            AND source_ip LIKE ?
        """

        parameters.append(
            f"%{source_ip}%"
        )


    query += """
        ORDER BY id DESC
    """


    cursor.execute(
        query,
        parameters
    )

    alerts = cursor.fetchall()

    connection.close()

    return alerts


# ============================================================
# GET STATISTICS
# ============================================================

def get_statistics():

    connection = get_connection()

    cursor = connection.cursor()


    # TOTAL

    cursor.execute(
        "SELECT COUNT(*) FROM alerts"
    )

    total = cursor.fetchone()[0]


    # HIGH

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'HIGH'
    """)

    high = cursor.fetchone()[0]


    # MEDIUM

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'MEDIUM'
    """)

    medium = cursor.fetchone()[0]


    # LOW

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE severity = 'LOW'
    """)

    low = cursor.fetchone()[0]


    # PORT SCANS

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE alert_type = 'PORT SCAN'
    """)

    port_scans = cursor.fetchone()[0]


    # BRUTE FORCE

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE alert_type LIKE '%BRUTE FORCE%'
    """)

    brute_force = cursor.fetchone()[0]


    # TRAFFIC

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE alert_type = 'TRAFFIC SPIKE'
    """)

    traffic_spikes = cursor.fetchone()[0]


    # ICMP

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE alert_type = 'ICMP ANOMALY'
    """)

    icmp_anomalies = cursor.fetchone()[0]


    connection.close()


    return {

        "total": total,

        "high": high,

        "medium": medium,

        "low": low,

        "port_scans": port_scans,

        "brute_force": brute_force,

        "traffic_spikes": traffic_spikes,

        "icmp_anomalies": icmp_anomalies

    }


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def dashboard():

    alerts = get_alerts()

    statistics = get_statistics()

    monitoring_status = (
        get_monitoring_status()
    )


    return render_template(

        "index.html",

        alerts=alerts,

        statistics=statistics,

        monitoring_status=monitoring_status,

        current_severity=request.args.get(
            "severity",
            ""
        ),

        current_attack=request.args.get(
            "attack_type",
            ""
        ),

        current_source=request.args.get(
            "source_ip",
            ""
        )

    )


# ============================================================
# START MONITORING
# ============================================================

@app.route("/start")
def start_monitoring():

    set_monitoring_status(
        "RUNNING"
    )

    return redirect(
        url_for("dashboard")
    )


# ============================================================
# STOP MONITORING
# ============================================================

@app.route("/stop")
def stop_monitoring():

    set_monitoring_status(
        "STOPPED"
    )

    return redirect(
        url_for("dashboard")
    )


# ============================================================
# ALERT DETAILS
# ============================================================

@app.route("/alert/<int:alert_id>")
def alert_details(alert_id):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            alert_type,
            source_ip,
            ports,
            severity
        FROM alerts
        WHERE id = ?
    """, (
        alert_id,
    ))

    alert = cursor.fetchone()

    connection.close()


    if alert is None:

        return (
            "Alert not found",
            404
        )


    return render_template(
        "alert_details.html",
        alert=alert
    )


# ============================================================
# START FLASK
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )