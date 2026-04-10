from dpi_engine import DPIEngine
from types import FiveTuple

# Fake packet class
class Packet:
    def __init__(self, src_ip, dst_ip, domain):
        self.tuple = FiveTuple(src_ip, dst_ip, 1234, 80, 6)
        self.domain = domain


if __name__ == "__main__":
    dpi = DPIEngine()

    # Add rules
    dpi.rules.block_app("YOUTUBE")
    dpi.rules.block_domain("facebook")

    packets = [
        Packet("10.0.0.1", "8.8.8.8", "youtube.com"),
        Packet("10.0.0.2", "8.8.8.8", "google.com"),
        Packet("10.0.0.3", "8.8.8.8", "facebook.com"),
    ]

    for p in packets:
        result = dpi.process_packet(p)
        print(p.tuple, "=>", result)