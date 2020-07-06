import sys
import os
path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(path)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '\\models')
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '\\rsa')
import rsa.rsa as rsa
import models.client as cl
import models.database as db
import socket
import ca_session as session
import threading


class CertificateAuthority:
    def __init__(self, ip, port):
        self.database = db.Database()
        self.decryptor = rsa.Decryptor()
        self.decryptor.fixed_keys(7, 41)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip = ip
        self.port = port

    def start(self):
        self.socket.bind((self.ip, self.port))
        self.socket.listen(5)
        while True:
            con, adr = self.socket.accept()
            t = threading.Thread(target=self.run_client_session, args=(con,))
            t.start()

    def run_client_session(self, connection):
        client_session = session.Session(self.database, connection, self.decryptor)
        client_session.handle_request()
