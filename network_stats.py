from collections import Counter


# ========================================
# NETWORK STATISTICS
# ========================================

class NetworkStats:

    def __init__(self):

        self.total_packets = 0

        self.tcp_packets = 0

        self.udp_packets = 0

        self.ipv4_packets = 0

        self.ipv6_packets = 0

        self.other_packets = 0

        self.source_ips = Counter()

        self.destination_ips = Counter()

        self.destination_ports = Counter()


    # ====================================
    # RECORD PACKET
    # ====================================

    def record_packet(
        self,
        source_ip=None,
        destination_ip=None,
        protocol=None,
        destination_port=None
    ):

        self.total_packets += 1


        # -------------------------------
        # Protocol
        # -------------------------------

        if protocol == "TCP":

            self.tcp_packets += 1

        elif protocol == "UDP":

            self.udp_packets += 1

        else:

            self.other_packets += 1


        # -------------------------------
        # IP version
        # -------------------------------

        if source_ip:

            if ":" in source_ip:

                self.ipv6_packets += 1

            else:

                self.ipv4_packets += 1


        # -------------------------------
        # Source IP
        # -------------------------------

        if source_ip:

            self.source_ips[source_ip] += 1


        # -------------------------------
        # Destination IP
        # -------------------------------

        if destination_ip:

            self.destination_ips[destination_ip] += 1


        # -------------------------------
        # Destination port
        # -------------------------------

        if destination_port != "-" and destination_port is not None:

            self.destination_ports[destination_port] += 1


    # ====================================
    # GET STATISTICS
    # ====================================

    def get_statistics(self):

        top_source = None

        top_destination = None

        top_port = None


        if self.source_ips:

            top_source = self.source_ips.most_common(1)[0]


        if self.destination_ips:

            top_destination = self.destination_ips.most_common(1)[0]


        if self.destination_ports:

            top_port = self.destination_ports.most_common(1)[0]


        return {

            "total_packets": self.total_packets,

            "tcp_packets": self.tcp_packets,

            "udp_packets": self.udp_packets,

            "ipv4_packets": self.ipv4_packets,

            "ipv6_packets": self.ipv6_packets,

            "other_packets": self.other_packets,

            "top_source_ip": top_source,

            "top_destination_ip": top_destination,

            "top_destination_port": top_port

        }


# ========================================
# CREATE GLOBAL STATISTICS OBJECT
# ========================================

network_stats = NetworkStats()