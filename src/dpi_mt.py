import threading
import queue
import hashlib
from collections import defaultdict


# =========================
# Thread Safe Queue
# =========================
class TSQueue:
    def __init__(self, max_size=10000):
        self.q = queue.Queue(maxsize=max_size)

    def push(self, item):
        self.q.put(item)

    def pop(self, timeout=0.1):
        try:
            return self.q.get(timeout=timeout)
        except:
            return None


# =========================
# Packet
# =========================
class Packet:
    def __init__(self, pid, src_ip, dst_ip, domain):
        self.id = pid
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.domain = domain


# =========================
# Rules
# =========================
class Rules:
    def __init__(self):
        self.blocked_ips = set()
        self.blocked_domains = []
        self.lock = threading.Lock()

    def block_ip(self, ip):
        with self.lock:
            self.blocked_ips.add(ip)

    def block_domain(self, dom):
        with self.lock:
            self.blocked_domains.append(dom)

    def is_blocked(self, ip, domain):
        with self.lock:
            if ip in self.blocked_ips:
                return True
            return any(d in domain for d in self.blocked_domains)


# =========================
# Fast Path (Worker)
# =========================
class FastPath:
    def __init__(self, fid, rules, output_q):
        self.id = fid
        self.rules = rules
        self.output_q = output_q
        self.q = TSQueue()
        self.running = False
        self.processed = 0

    def start(self):
        self.running = True
        threading.Thread(target=self.run, daemon=True).start()

    def stop(self):
        self.running = False

    def run(self):
        while self.running:
            pkt = self.q.pop()
            if not pkt:
                continue

            self.processed += 1

            if self.rules.is_blocked(pkt.src_ip, pkt.domain):
                continue  # DROP
            else:
                self.output_q.push(pkt)


# =========================
# Load Balancer
# =========================
class LoadBalancer:
    def __init__(self, lid, fps):
        self.id = lid
        self.fps = fps
        self.q = TSQueue()
        self.running = False

    def start(self):
        self.running = True
        threading.Thread(target=self.run, daemon=True).start()

    def stop(self):
        self.running = False

    def run(self):
        while self.running:
            pkt = self.q.pop()
            if not pkt:
                continue

            idx = hash(pkt.src_ip) % len(self.fps)
            self.fps[idx].q.push(pkt)


# =========================
# DPI Engine
# =========================
class DPIEngine:
    def __init__(self, lbs=2, fps_per_lb=2):
        self.rules = Rules()
        self.output_q = TSQueue()

        total_fps = lbs * fps_per_lb

        # Create FP
        self.fps = [FastPath(i, self.rules, self.output_q) for i in range(total_fps)]

        # Create LB
        self.lbs = []
        for i in range(lbs):
            start = i * fps_per_lb
            self.lbs.append(LoadBalancer(i, self.fps[start:start+fps_per_lb]))

    def start(self):
        for fp in self.fps:
            fp.start()
        for lb in self.lbs:
            lb.start()

    def stop(self):
        for lb in self.lbs:
            lb.stop()
        for fp in self.fps:
            fp.stop()

    def process_packets(self, packets):
        for i, pkt in enumerate(packets):
            lb_idx = i % len(self.lbs)
            self.lbs[lb_idx].q.push(pkt)


# =========================
# Demo Main
# =========================
if __name__ == "__main__":
    engine = DPIEngine()

    # rules
    engine.rules.block_domain("facebook")
    engine.rules.block_ip("10.0.0.1")

    engine.start()

    packets = [
        Packet(1, "10.0.0.1", "8.8.8.8", "youtube.com"),
        Packet(2, "10.0.0.2", "8.8.8.8", "google.com"),
        Packet(3, "10.0.0.3", "8.8.8.8", "facebook.com"),
    ]

    engine.process_packets(packets)

    import time
    time.sleep(1)

    print("\nForwarded Packets:")
    while True:
        pkt = engine.output_q.pop()
        if not pkt:
            break
        print(pkt.src_ip, "->", pkt.domain)