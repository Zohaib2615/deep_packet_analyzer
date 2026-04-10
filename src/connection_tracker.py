class Connection:
    def __init__(self, tuple_):
        self.tuple = tuple_
        self.app_type = None
        self.domain = ""
        self.blocked = False


class ConnectionTracker:
    def __init__(self):
        self.connections = {}

    def get_or_create(self, tuple_):
        key = str(tuple_)
        if key not in self.connections:
            self.connections[key] = Connection(tuple_)
        return self.connections[key]