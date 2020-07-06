import socket
import rsa.rsa as rsa
import handler
import network as net
import constants
import threading
import models.details as details


class Server:
    def __init__(self, user_details, ca_server_details):
        self.details = user_details
        self.ca_server_details = ca_server_details
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.certificate = handler.get_certificate_from_ca_server(self.details.id, self.details.name,
                                                                  self.ca_server_details, self.details.decryptor)
        self.bind_to_clients = False
        self.clients = {}

    def start(self, ip, port):
        self.socket.bind((ip, port))
        self.socket.listen(5)
        threading.Thread(target=self.bind).start()

    def bind(self):
        self.bind_to_clients = True
        while self.bind_to_clients:
            conn, addr = self.socket.accept()
            threading.Thread(target=self.session_handler, args=(conn,)).start()

    def session_handler(self, connection):
        session = handler.Handler(net.Network(connection), self.details.decryptor.copy(),
                                  self.ca_server_details.public_key, self.certificate)
        session.handshake(constants.SERVER_HANDSHAKE)
        self.clients[session.client_name] = session

    def close(self):
        self.bind_to_clients = False
        self.socket.close()

    def get_client(self, client_name):
        if client_name in self.clients:
            return self.clients[client_name]
        else:
            return None

user = details.UserDetails()
user.id = 1551
user.name = "sample_user1"
user.decryptor = rsa.Decryptor()

ca_details = details.CAServerDetails(socket.gethostname(), 32410, (287, 7))

server = Server(user, ca_details)
server.start(socket.gethostname(), 32411)

