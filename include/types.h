from enum import Enum

class AppType(Enum):
    UNKNOWN = 0
    HTTP = 1
    HTTPS = 2
    DNS = 3
    GOOGLE = 4
    YOUTUBE = 5
    FACEBOOK = 6


class FiveTuple:
    def __init__(self, src_ip, dst_ip, src_port, dst_port, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

    def __str__(self):
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"