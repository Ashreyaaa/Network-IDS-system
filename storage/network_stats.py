import json
import os


STATS_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "network_stats.json"
)


DEFAULT_STATS = {

    "total_packets": 0,

    "tcp_packets": 0,

    "udp_packets": 0,

    "ipv4_packets": 0,

    "ipv6_packets": 0,

    "other_packets": 0,

    "top_source_ip": None,

    "top_destination_ip": None,

    "top_destination_port": None

}


def save_statistics(stats):

    try:

        with open(
            STATS_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                stats,
                file,
                indent=4
            )

    except Exception as error:

        print(
            f"[!] Could not save network statistics: {error}"
        )


def load_statistics():

    if not os.path.exists(STATS_FILE):

        return DEFAULT_STATS.copy()

    try:

        with open(
            STATS_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        return {
            **DEFAULT_STATS,
            **data
        }

    except Exception:

        return DEFAULT_STATS.copy()