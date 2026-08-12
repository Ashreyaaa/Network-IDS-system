from datetime import datetime


LOG_FILE = "logs/ids.log"


def log_alert(alert_type, source_ip, ports, severity):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, "a") as file:

        file.write("\n")
        file.write("========================================\n")
        file.write("SECURITY ALERT\n")
        file.write("========================================\n")
        file.write(f"Time:       {timestamp}\n")
        file.write(f"Type:       {alert_type}\n")
        file.write(f"Source IP:  {source_ip}\n")
        file.write(f"Ports:      {sorted(ports)}\n")
        file.write(f"Severity:   {severity}\n")
        file.write("========================================\n")