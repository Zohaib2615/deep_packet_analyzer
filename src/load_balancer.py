import threading
import hashlib
from collections import defaultdict


# =========================
# Load Balancer
# =========================
class LoadBalancer:

    def __init__(self, lb_id, fp_queues, fp_start_id=0):
        self.lb_id = lb_id
        self.fp_start_id = fp_start_id
        self.fp_queues = fp_queues
        self.num_fps = len(fp_queues)

        self.input_queue = []
        self.lock = threading.Lock()

        self.running = False

        # stats
        self.packets_received = 0
        self.packets_dispatched = 0
        self.per_fp_counts = [0] * self.num_fps

    def start(self):
        if self.running:
            return

        self.running = True
        threading.Thread(target=self.run, daemon=True).start()

        print(f"[LB{self.lb_id}] Started (FP{self.fp_start_id}-FP{self.fp_start_id + self.num_fps - 1})")

    def stop(self):
        self.running = False
        print(f"[LB{self.lb_id}] Stopped")

    def push(self, job):
        with self.lock:
            self.input_queue.append(job)

    def pop(self):
        with self.lock:
            if self.input_queue:
                return self.input_queue.pop(0)
        return None

    def run(self):
        while self.running:
            job = self.pop()
            if not job:
                continue

            self.packets_received += 1

            fp_index = self.select_fp(job.tuple)

            self.fp_queues[fp_index].push(job)

            self.packets_dispatched += 1
            self.per_fp_counts[fp_index] += 1

    def select_fp(self, tuple_):
        key = str(tuple_)
        hash_val = int(hashlib.md5(key.encode()).hexdigest(), 16)
        return hash_val % self.num_fps


# =========================
# Load Balancer Manager
# =========================
class LBManager:

    def __init__(self, num_lbs, fps_per_lb, fp_queues):

        self.lbs = []
        self.fps_per_lb = fps_per_lb

        for lb_id in range(num_lbs):
            start = lb_id * fps_per_lb
            lb_fp_queues = fp_queues[start:start + fps_per_lb]

            lb = LoadBalancer(lb_id, lb_fp_queues, start)
            self.lbs.append(lb)

        print(f"[LBManager] Created {num_lbs} LBs, {fps_per_lb} FPs each")

    def start_all(self):
        for lb in self.lbs:
            lb.start()

    def stop_all(self):
        for lb in self.lbs:
            lb.stop()

    def get_lb_for_packet(self, tuple_):
        key = str(tuple_)
        hash_val = int(hashlib.md5(key.encode()).hexdigest(), 16)
        return self.lbs[hash_val % len(self.lbs)]

    def get_stats(self):
        total_received = 0
        total_dispatched = 0

        for lb in self.lbs:
            total_received += lb.packets_received
            total_dispatched += lb.packets_dispatched

        return {
            "total_received": total_received,
            "total_dispatched": total_dispatched
        }