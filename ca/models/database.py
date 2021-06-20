import pickle, tabulate
from . import client as db_client

class Database:
    """
    Pickle library-based serialization database.
    * Stores client's is, password, activity status, public key, certificate validity and access date
    * Allow addition, removal and extraction operations
    * Supports reading from and writing to file, for permanence
    """
    def __init__(self):
        self.clients = {}
        self.current_file = None

    def exist(self, client_id):
        """
        Returns whether a client exists in the database
        :param client_id: str; client's id
        :return: bool
        """
        return client_id in self.clients

    def get(self, client_id):
        """
        Returns requested client by id if exists
        :param client_id: str;
        :return: Client or None
        """
        if self.exist(client_id):
            return self.clients[client_id]
        else:
            return None

    def add(self, client):
        """
        Adds new client to database
        :param client: Client
        :return: None
        """
        if not self.exist(client.id):
            self.clients[client.id] = client

    def remove(self, client_id, get_client=False):
        """
        Removes client by id from database and returns it if requested
        :param client_id: str
        :param get_client: bool
        :return: None or Client
        """
        if get_client:
            return self.clients.pop(db_client.id, None)
        else:
            if self.exist(client_id):
                del self.clients[client_id]

    def verify_client(self, client_id, password):
        """
        Verifies client's password
        :param client_id: str
        :param password: str
        :return: bool
        """
        client = self.get(client_id)
        if client:
            if client.compare_password(password):
                return True
        return False

    def save_to_file(self, path=None):
        """
        Saves database to file. Throws and exception if new path or current filename aren't defined
        :param path: str
        :return: None
        """
        clients = self.clients.values()
        clients = [client.serialize() for client in clients]
        if not path and self.current_file:
            path = self.current_file
        elif not path:
            raise Exception("Filename not specified")
        with open(path, "wb") as dbfile:
         pickle.dump(clients, dbfile, protocol=pickle.HIGHEST_PROTOCOL)

    def load(self, path):
        """
        Loads database from file by give file path
        :param path: str
        :return: None
        """
        with open(path, "rb") as dbfile:
            clients_list = pickle.load(dbfile)
            for client in clients_list:
                self.add(db_client.Client(client["id"], client["password"], client["active"], client["recentKey"],
                                          client["validity"], client["access"]))
            # saves current path fro further saves
            self.current_file = path

    def print(self):
        """
        Prints all database clients
        :return: None
        """
        values = self.clients.values()
        lst = []
        for client in values:
            lst.append(client.get_values())

        print(tabulate.tabulate(lst, headers=("id", "Status", "recent key", "validity", "access time")))

