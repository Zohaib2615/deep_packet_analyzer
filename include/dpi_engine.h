from types import SimpleNamespace
from rule_manager import RuleManager
from connection_tracker import ConnectionTracker
from types import AppType


class DPIEngine:
    def __init__(self):
        self.rules = RuleManager()
        self.tracker = ConnectionTracker()

    def classify(self, domain):
        domain = domain.lower()

        if "youtube" in domain:
            return AppType.YOUTUBE
        if "google" in domain:
            return AppType.GOOGLE
        if "facebook" in domain:
            return AppType.FACEBOOK
        return AppType.UNKNOWN

    def process_packet(self, packet):
        conn = self.tracker.get_or_create(packet.tuple)

        if not conn.app_type:
            conn.app_type = self.classify(packet.domain)
            conn.domain = packet.domain

        if self.rules.should_block(packet.tuple.src_ip, conn.app_type, conn.domain):
            conn.blocked = True
            return "DROP"
        return "FORWARD"