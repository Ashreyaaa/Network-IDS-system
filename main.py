from scapy.all import (
    sniff,
    conf,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP
)

from datetime import datetime

import time
import os
from collections import Counter

from alerts.alert_manager import generate_alert
from storage.database import initialize_database
from storage.network_stats import save_statistics


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

STATUS_FILE = os.path.join(
    BASE_DIR,
    "monitoring.status"
)


# ============================================================
# INITIALIZE DATABASE
# ============================================================

initialize_database()


# ============================================================
# MONITORING STATUS
# ============================================================

def set_monitoring_status(status):

    try:

        with open(
            STATUS_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(status)

    except Exception as error:

        print(
            f"[!] Could not update monitoring status: {error}"
        )


def is_monitoring_enabled():

    try:

        with open(
            STATUS_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            status = file.read().strip()

            return status == "RUNNING"

    except FileNotFoundError:

        return True

    except Exception:

        return True


# ============================================================
# START MONITORING
# ============================================================

set_monitoring_status("RUNNING")


# ============================================================
# TRACKERS
# ============================================================

connection_tracker = {}

brute_force_tracker = {}

icmp_tracker = {}

traffic_tracker = []

suspicious_ips = set()

last_alert_time = {}


# ============================================================
# AUTHENTICATION PORTS
# ============================================================

AUTH_PORTS = {

    21: "FTP",

    22: "SSH",

    23: "TELNET",

    25: "SMTP",

    110: "POP3",

    143: "IMAP",

    3389: "RDP"

}


# ============================================================
# DETECTION SETTINGS
# ============================================================

TIME_WINDOW = 10


# Port scan:
# 10 unique TCP destination ports in 10 seconds
PORT_SCAN_THRESHOLD = 10


# Brute force:
# 8 attempts to same authentication service
BRUTE_FORCE_THRESHOLD = 8

BRUTE_FORCE_WINDOW = 30


# Traffic spike:
# Increased from 100 to reduce false positives
TRAFFIC_THRESHOLD = 250

TRAFFIC_WINDOW = 10


# ICMP anomaly
ICMP_THRESHOLD = 30

ICMP_WINDOW = 10


# Alert cooldown
ALERT_COOLDOWN = 60


# ============================================================
# NETWORK STATISTICS
# ============================================================

total_packets = 0

tcp_packets = 0

udp_packets = 0

ipv4_packets = 0

ipv6_packets = 0

other_packets = 0


source_counter = Counter()

destination_counter = Counter()

destination_port_counter = Counter()


# ============================================================
# ALERT COOLDOWN
# ============================================================

def can_generate_alert(alert_key):

    current_time = time.time()

    if alert_key not in last_alert_time:

        last_alert_time[alert_key] = current_time

        return True

    if (
        current_time
        - last_alert_time[alert_key]
        >= ALERT_COOLDOWN
    ):

        last_alert_time[alert_key] = current_time

        return True

    return False


# ============================================================
# SAVE NETWORK STATISTICS
# ============================================================

def update_statistics():

    top_source = (
        source_counter.most_common(1)[0][0]
        if source_counter
        else None
    )

    top_destination = (
        destination_counter.most_common(1)[0][0]
        if destination_counter
        else None
    )

    top_port = (
        destination_port_counter.most_common(1)[0][0]
        if destination_port_counter
        else None
    )

    statistics = {

        "total_packets": total_packets,

        "tcp_packets": tcp_packets,

        "udp_packets": udp_packets,

        "ipv4_packets": ipv4_packets,

        "ipv6_packets": ipv6_packets,

        "other_packets": other_packets,

        "top_source_ip": top_source,

        "top_destination_ip": top_destination,

        "top_destination_port": top_port

    }

    save_statistics(statistics)


# ============================================================
# PACKET PROCESSING
# ============================================================

def packet_received(packet):

    global total_packets
    global tcp_packets
    global udp_packets
    global ipv4_packets
    global ipv6_packets
    global other_packets

    # --------------------------------------------------------
    # STOP CHECK
    # --------------------------------------------------------

    if not is_monitoring_enabled():

        return

    current_time = time.time()

    timestamp = datetime.now().strftime(
        "%H:%M:%S"
    )


    # --------------------------------------------------------
    # PACKET COUNT
    # --------------------------------------------------------

    total_packets += 1


    # --------------------------------------------------------
    # IP INFORMATION
    # --------------------------------------------------------

    source_ip = None

    destination_ip = None


    if IP in packet:

        source_ip = packet[IP].src

        destination_ip = packet[IP].dst

        ipv4_packets += 1


    elif IPv6 in packet:

        source_ip = packet[IPv6].src

        destination_ip = packet[IPv6].dst

        ipv6_packets += 1


    else:

        other_packets += 1

        return


    source_counter[source_ip] += 1

    destination_counter[destination_ip] += 1


    # --------------------------------------------------------
    # PROTOCOL
    # --------------------------------------------------------

    protocol = "Other"

    source_port = "-"

    destination_port = "-"


    if TCP in packet:

        protocol = "TCP"

        tcp_packets += 1

        source_port = packet[TCP].sport

        destination_port = packet[TCP].dport

        destination_port_counter[
            destination_port
        ] += 1


    elif UDP in packet:

        protocol = "UDP"

        udp_packets += 1

        source_port = packet[UDP].sport

        destination_port = packet[UDP].dport

        destination_port_counter[
            destination_port
        ] += 1


    # --------------------------------------------------------
    # TRAFFIC TRACKING
    # --------------------------------------------------------

    traffic_tracker.append(
        current_time
    )


    traffic_tracker[:] = [

        packet_time

        for packet_time in traffic_tracker

        if current_time - packet_time
        <= TRAFFIC_WINDOW

    ]


    packet_count = len(
        traffic_tracker
    )


    # --------------------------------------------------------
    # CONNECTION TRACKING
    # IMPORTANT:
    # Only TCP SYN packets are considered for port scans.
    # This avoids treating normal response traffic as scans.
    # --------------------------------------------------------

    if TCP in packet:

        flags = packet[TCP].flags

        syn_packet = (
            flags & 0x02
            and not (flags & 0x10)
        )

        if syn_packet:

            if source_ip not in connection_tracker:

                connection_tracker[
                    source_ip
                ] = []


            connection_tracker[
                source_ip
            ].append(

                (
                    destination_port,
                    current_time
                )

            )


            connection_tracker[
                source_ip
            ] = [

                item

                for item in connection_tracker[
                    source_ip
                ]

                if current_time - item[1]
                <= TIME_WINDOW

            ]


    # --------------------------------------------------------
    # UNIQUE PORTS
    # --------------------------------------------------------

    unique_ports = set()


    if source_ip in connection_tracker:

        for port, connection_time in (
            connection_tracker[source_ip]
        ):

            unique_ports.add(port)


    port_count = len(
        unique_ports
    )


    # --------------------------------------------------------
    # TERMINAL INFORMATION
    # --------------------------------------------------------

    print("----------------------------------------")

    print(
        f"TIME:             {timestamp}"
    )

    print(
        f"SOURCE IP:        {source_ip}"
    )

    print(
        f"DESTINATION IP:   {destination_ip}"
    )

    print(
        f"PROTOCOL:         {protocol}"
    )

    print(
        f"SOURCE PORT:      {source_port}"
    )

    print(
        f"DESTINATION PORT: {destination_port}"
    )

    print(
        f"PACKETS / 10 SEC: {packet_count}"
    )

    print(
        f"UNIQUE PORTS:     {port_count}"
    )

    print("----------------------------------------")


    # ========================================================
    # PORT SCAN DETECTION
    # ========================================================

    if port_count >= PORT_SCAN_THRESHOLD:

        alert_key = (
            f"port_scan_{source_ip}"
        )


        if can_generate_alert(
            alert_key
        ):

            suspicious_ips.add(
                source_ip
            )

            generate_alert(

                alert_type="PORT SCAN",

                source_ip=source_ip,

                ports=unique_ports,

                severity="HIGH"

            )


    # ========================================================
    # BRUTE FORCE DETECTION
    # ========================================================

    if (
        destination_port != "-"
        and destination_port in AUTH_PORTS
    ):

        service = AUTH_PORTS[
            destination_port
        ]


        if source_ip not in brute_force_tracker:

            brute_force_tracker[
                source_ip
            ] = []


        brute_force_tracker[
            source_ip
        ].append(

            (
                destination_port,
                current_time
            )

        )


        brute_force_tracker[
            source_ip
        ] = [

            item

            for item in brute_force_tracker[
                source_ip
            ]

            if current_time - item[1]
            <= BRUTE_FORCE_WINDOW

        ]


        service_attempts = sum(

            1

            for port, attempt_time
            in brute_force_tracker[
                source_ip
            ]

            if port == destination_port

        )


        print(
            f"AUTH SERVICE:    {service}"
        )

        print(
            f"AUTH ATTEMPTS:   {service_attempts}"
        )


        if (
            service_attempts
            >= BRUTE_FORCE_THRESHOLD
        ):

            alert_key = (
                f"brute_force_"
                f"{source_ip}_"
                f"{destination_port}"
            )


            if can_generate_alert(
                alert_key
            ):

                suspicious_ips.add(
                    source_ip
                )

                generate_alert(

                    alert_type=(
                        f"POSSIBLE "
                        f"{service} BRUTE FORCE"
                    ),

                    source_ip=source_ip,

                    ports={
                        destination_port
                    },

                    severity="HIGH"

                )


    # ========================================================
    # TRAFFIC SPIKE
    # ========================================================

    if packet_count >= TRAFFIC_THRESHOLD:

        alert_key = "traffic_spike"


        if can_generate_alert(
            alert_key
        ):

            generate_alert(

                alert_type="TRAFFIC SPIKE",

                source_ip="NETWORK",

                ports=set(),

                severity="MEDIUM"

            )


    # ========================================================
    # ICMP / PING ANOMALY
    # ========================================================

    if ICMP in packet:

        if source_ip not in icmp_tracker:

            icmp_tracker[
                source_ip
            ] = []


        icmp_tracker[
            source_ip
        ].append(
            current_time
        )


        icmp_tracker[
            source_ip
        ] = [

            packet_time

            for packet_time in icmp_tracker[
                source_ip
            ]

            if current_time - packet_time
            <= ICMP_WINDOW

        ]


        icmp_count = len(
            icmp_tracker[source_ip]
        )


        if icmp_count >= ICMP_THRESHOLD:

            alert_key = (
                f"icmp_anomaly_{source_ip}"
            )


            if can_generate_alert(
                alert_key
            ):

                suspicious_ips.add(
                    source_ip
                )

                generate_alert(

                    alert_type="ICMP ANOMALY",

                    source_ip=source_ip,

                    ports=set(),

                    severity="MEDIUM"

                )


    # ========================================================
    # UPDATE STATISTICS
    # ========================================================

    if total_packets % 10 == 0:

        update_statistics()


# ============================================================
# START IDS
# ============================================================

print()
print("========================================")
print("       NETWORK INTRUSION IDS")
print("========================================")

print("[+] Database initialized")

print("[+] Monitoring status: ONLINE")

print("[+] Connection tracking enabled")

print("[+] Port scan detection enabled")

print("[+] Brute-force detection enabled")

print("[+] Traffic-spike detection enabled")

print("[+] ICMP anomaly detection enabled")

print("[+] Suspicious-IP tracking enabled")

print("[+] Network statistics enabled")

print("[+] Press CTRL+C to stop")

print()


# ============================================================
# SELECT INTERFACE
# ============================================================

try:

    wifi_interface = conf.ifaces.dev_from_index(4)

    print(
        "[+] Wi-Fi interface selected successfully"
    )

    print(
        f"[+] Interface: {wifi_interface}"
    )

except Exception as error:

    print(
        f"[!] Could not select interface 4: {error}"
    )

    print(
        "[!] Using Scapy default interface"
    )

    wifi_interface = conf.iface


# ============================================================
# PACKET CAPTURE
# ============================================================

try:

    sniff(

        iface=wifi_interface,

        prn=packet_received,

        store=False

    )


except KeyboardInterrupt:

    set_monitoring_status(
        "STOPPED"
    )

    update_statistics()

    print()
    print("========================================")
    print("          NETWORK IDS STOPPED")
    print("========================================")

    print(
        "[+] Monitoring stopped"
    )

    print(
        "[+] Alerts saved to SQLite"
    )

    print(
        "[+] Network statistics saved"
    )


except Exception as error:

    set_monitoring_status(
        "STOPPED"
    )

    print()
    print("========================================")
    print("             IDS ERROR")
    print("========================================")

    print(
        f"[!] {error}"
    )