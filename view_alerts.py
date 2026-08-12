import sqlite3


DATABASE_FILE = "storage/ids.db"


connection = sqlite3.connect(DATABASE_FILE)

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
    ORDER BY id DESC
""")


alerts = cursor.fetchall()


print()
print("========================================")
print("          IDS ALERT HISTORY")
print("========================================")


if not alerts:

    print()
    print("No alerts have been recorded yet.")
    print()


else:

    for alert in alerts:

        alert_id = alert[0]
        timestamp = alert[1]
        alert_type = alert[2]
        source_ip = alert[3]
        ports = alert[4]
        severity = alert[5]


        print()
        print("----------------------------------------")

        print(f"ID:          {alert_id}")
        print(f"Time:        {timestamp}")
        print(f"Type:        {alert_type}")
        print(f"Source IP:   {source_ip}")
        print(f"Ports:       {ports}")
        print(f"Severity:    {severity}")


print()
print("========================================")


connection.close()