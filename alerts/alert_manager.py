from datetime import datetime

from storage.database import save_alert


def generate_alert(
    alert_type,
    source_ip,
    ports,
    severity
):

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # Convert ports to readable text
    if isinstance(ports, set):
        ports = sorted(list(ports))

    ports_text = str(ports)

    # Save to database
    save_alert(
        timestamp,
        alert_type,
        source_ip,
        ports_text,
        severity
    )

    # Terminal alert
    print()
    print("========================================")
    print("🚨 SECURITY ALERT")
    print("========================================")

    print(f"Time:       {timestamp}")
    print(f"Type:       {alert_type}")
    print(f"Source IP:  {source_ip}")
    print(f"Ports:      {ports_text}")
    print(f"Severity:   {severity}")

    print("========================================")
    print()