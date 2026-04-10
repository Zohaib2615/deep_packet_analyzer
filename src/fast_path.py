import threading
from collections import defaultdict


class Connection:
    def __init__(self, tuple_):
        self.tuple = tuple_
        self.state = "NEW"
        self.app_type = "UNKNOWN"
        self.sni = ""
        self.packets = 0
        self.bytes = 0


class ConnectionTracker:
    def __init__(self):
        self.connections = {}

    def get_or_create(self, tuple_):
        key = str(tuple_)
        if key not in self.connections:
            self.connections[key] = Connection(tuple_)
        return self.connections[key]

    def update(self, conn, size):
        conn.packets += 1
        conn.bytes += size

    def classify(self, conn, app, sni):
        conn.app_type = app
        conn.sni = sni
        conn.state = "CLASSIFIED"

    def block(self, conn):
        conn.state = "BLOCKED"


# =========================
# Fast Path Processor
# =========================
class FastPathProcessor:

    def __init__(self, fp_id, rule_manager, output_callback):
        self.fp_id = fp_id
        self.rules = rule_manager
        self.output_callback = output_callback

        self.queue = []
        self.lock = threading.Lock()
        self.running = False

        self.conn_tracker = ConnectionTracker()

        # stats
        self.processed = 0
        self.forwarded = 0
        self.dropped = 0

    def start(self):
        self.running = True
        threading.Thread(target=self.run, daemon=True).start()
        print(f"[FP{self.fp_id}] Started")

    def stop(self):
        self.running = False
        print(f"[FP{self.fp_id}] Stopped")

    def push(self, job):
        with self.lock:
            self.queue.append(job)

    def pop(self):
        with self.lock:
            if self.queue:
                return self.queue.pop(0)
        return None

    def run(self):
        while self.running:
            job = self.pop()
            if not job:
                continue

            self.processed += 1

            action = self.process_packet(job)

            if self.output_callback:
                self.output_callback(job, action)

            if action == "DROP":
                self.dropped += 1
            else:
                self.forwarded += 1

    # =========================
    # CORE DPI LOGIC
    # =========================
    def process_packet(self, job):

        conn = self.conn_tracker.get_or_create(job.tuple)

        # update stats
        self.conn_tracker.update(conn, len(job.data))

        # already blocked
        if conn.state == "BLOCKED":
            return "DROP"

        # classify
        if conn.state != "CLASSIFIED":
            self.inspect_payload(job, conn)

        # apply rules
        return self.check_rules(job, conn)

    # =========================
    # PAYLOAD INSPECTION
    # =========================
    def inspect_payload(self, job, conn):

        payload = job.payload

        # TLS (HTTPS)
        if job.dst_port == 443:
            if "youtube" in payload:
                self.conn_tracker.classify(conn, "YOUTUBE", "youtube.com")
                return

        # HTTP
        if job.dst_port == 80:
            if "Host:" in payload:
                host = payload.split("Host:")[1].split("\\r\\n")[0].strip()
                self.conn_tracker.classify(conn, "HTTP", host)
                return

        # DNS
        if job.dst_port == 53:
            self.conn_tracker.classify(conn, "DNS", "dns_query")
            return

        # fallback
        if job.dst_port == 80:
            conn.app_type = "HTTP"
        elif job.dst_port == 443:
            conn.app_type = "HTTPS"

    # =========================
    # RULE CHECK
    # =========================
    def check_rules(self, job, conn):

        if self.rules.should_block(job.src_ip, conn.app_type, conn.sni):
            print(f"[FP{self.fp_id}] BLOCKED {conn.sni}")
            self.conn_tracker.block(conn)
            return "DROP"

        return "FORWARD"