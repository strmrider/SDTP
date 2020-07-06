import sys
import os
path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(path)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '\\models')
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '\\rsa')
import socket
import rsa.rsa as rsa
import struct
import network as net
import constants
import models.certificate as cert


class Session:
    def __init__(self, connection, user_id, name, ca_public_key, decryptor):
        self.network = net.Network(connection)
        self.id = user_id
        self.name = name
        self.encryptor = rsa.Encryptor(ca_public_key[0], ca_public_key[1])
        self.decryptor = decryptor

    def encrypt_properties(self):
        public_key = self.decryptor.get_public_key()
        return ",".join(map(str, self.encryptor.encrypt(str(self.id)))),\
               ",".join(map(str, self.encryptor.encrypt(str(self.name)))),  \
               ",".join(map(str, self.encryptor.encrypt(str(public_key[0])))), \
               ",".join(map(str, self.encryptor.encrypt(str(public_key[1]))))

    def request_certificate(self):
        encryptions = self.encrypt_properties()
        header = struct.pack("! B B H H I I ", 13, 5, len(encryptions[0]), len(encryptions[1]),
                             len(encryptions[2]), len(encryptions[3]))
        full = header + encryptions[0] + encryptions[1] + encryptions[2] + encryptions[3]
        pack = bytearray(full)
        self.network.send(pack)

    def certification_response(self):
        raw_header = self.network.read_header()
        header = struct.unpack("!B H I I I", raw_header)
        if header[0] == constants.CERTIFICATE_APPROVAL:
            name = self.network.receive(header[1])
            key_n = self.network.receive(header[2])
            key_e = self.network.receive(header[3])
            signature = self.network.receive(header[4])
            signature = map(long, signature.split(","))
            if self.encryptor.verify_signature(signature, str(key_e)):
                return cert.Certificate(name, (key_n, key_e), signature)
            else:
                raise Exception("Unverified signature")
        elif header[0] == constants.CERTIFICATE_DENIAL:
            raise Exception("Certificate request denied")

    def close_session(self):
        self.network.close()


def receive_certificate(user_id, name, public_key, host, port, decryptor):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    session = Session(s, user_id, name, public_key, decryptor)
    try:
        session.request_certificate()
        certification = session.certification_response()
        session.close_session()
        return certification
    except Exception as e:
        print str(e)
        session.close_session()
        raise e

