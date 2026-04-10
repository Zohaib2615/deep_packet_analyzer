class RuleManager:
    def __init__(self):
        self.blocked_ips = set()
        self.blocked_apps = set()
        self.blocked_domains = []

    def block_ip(self, ip):
        self.blocked_ips.add(ip)

    def block_app(self, app):
        self.blocked_apps.add(app)

    def block_domain(self, domain):
        self.blocked_domains.append(domain)

    def should_block(self, ip, app, domain):
        if ip in self.blocked_ips:
            return True
        if app in self.blocked_apps:
            return True
        for d in self.blocked_domains:
            if d in domain:
                return True
        return False