class Database:
    def __init__(self):
        self.clients = {}

    def exist(self, client_id):
        return client_id in self.clients

    def get(self, client_id):
        if self.exist(client_id):
            return self.clients[client_id]
        else:
            return None

    def add(self, client):
        if not self.exist(client.id):
            self.clients[client.id] = client

    def remove(self, client_id, get_client=False):
        if get_client:
            return self.clients.pop(client.id, None)
        else:
            if self.exist(client_id):
                del self.clients[client_id]
