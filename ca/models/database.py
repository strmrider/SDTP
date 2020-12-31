import pickle, tabulate
from . import client as db_client

class Database:
    def __init__(self):
        self.clients = {}
        self.current_file = None

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
            return self.clients.pop(db_client.id, None)
        else:
            if self.exist(client_id):
                del self.clients[client_id]

    def verify_client(self, client_id, password):
        c = self.get(client_id)
        if c:
            if c.compare_password(password):
                return True
        return False

    def save_to_file(self, path=None):
        clients = self.clients.values()
        clients = [client.serialize() for client in clients]
        if not path and self.current_file:
            path = self.current_file
        elif not path:
            raise Exception("Filename not specified")
        with open(path, "wb") as dbfile:
         pickle.dump(clients, dbfile, protocol=pickle.HIGHEST_PROTOCOL)

    def load(self, path):
        with open(path, "rb") as dbfile:
            clients_list = pickle.load(dbfile)
            for client in clients_list:
                self.add(db_client.Client(client["id"], client["password"], client["active"], client["recentKey"],
                                          client["validity"], client["access"]))
            self.current_file = path

    def print(self):
        values = self.clients.values()
        lst = []
        for client in values:
            lst.append(client.get_values())

        print(tabulate.tabulate(lst, headers=("id", "Status", "recent key", "validity", "access time")))

