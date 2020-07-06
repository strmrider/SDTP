import sys
import os
path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(path)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '\\models')
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '\\rsa')
import network as net
import rsa.rsa as rsa
import models.client as cl
import models.certificate as cert
import struct
import constants

class Session:
    def __init__(self, database, connection, decryptor):
        self.database = database
        self.network = net.Network(connection)
        self.decryptor = decryptor

    def handle_request(self):
        header = self.network.read_header()
        client, key = self.unpack_client(header)
        if self.database.exist(int(client.id)):
            certificate = cert.Certificate(client.name, key, None)
            certificate.sign(self.decryptor.sign_message(key[1]))
            pack = certificate.pack(constants.CERTIFICATE_APPROVAL)
            self.network.send(pack)
        else:
            self.send_denial_response(key[1])

    def unpack_client(self, header):
        components = struct.unpack("! B H H I I", header)
        id_len = components[1]
        name_len = components[2]
        key_len = (components[3], components[4])
        client_id = self.network.receive(id_len)
        name = self.network.receive(name_len)
        key_n = self.network.receive(key_len[0])
        key_e = self.network.receive(key_len[1])
        return cl.Client(self.decrypt_property(client_id), self.decrypt_property(name)), \
                        (self.decrypt_property(key_n), self.decrypt_property(key_e))

    def send_denial_response(self, key):
        signature = str(self.decryptor.sign_message(key))
        header = struct.pack("!B B I", 5, constants.CERTIFICATE_DENIAL, len(signature))
        pack = bytearray(header + signature)
        self.network.send(pack)

    def decrypt_property(self, property):
        array_long = map(long, property.split(","))
        return self.decryptor.decrypt(array_long)

