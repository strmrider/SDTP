import socket
import ca_server.ca_client as ca_server
import rsa.rsa as rsa
import handler
import network as net
import constants
import models.details as details


user_details = details.UserDetails()
user_details.id = 1552
user_details.name = "sample_user2"
user_details.decryptor = rsa.Decryptor()

ca_details = details.CAServerDetails(socket.gethostname(), 32410, (287, 7))


class Client:
    def __init__(self, user_details, ca_server_details):
        self.details = user_details
        self.ca_server_details = ca_server_details
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.certificate = handler.get_certificate_from_ca_server(self.details.id, self.details.name,
                                                                  self.ca_server_details, self.details.decryptor)
        self.session = None

    def connect(self, ip, port):
        self.socket.connect((ip, port))
        self.session = handler.Handler(net.Network(self.socket), self.details.decryptor.copy(),
                                       self.ca_server_details.public_key, self.certificate)
        self.session.handshake(constants.CLIENT_HANDSHAKE)

    def get_session(self):
        return self.session

    def close(self):
        self.socket.close()

client = Client(user_details, ca_details)
client.connect(socket.gethostname(), 32411)
client.get_session().send_text("hello")
