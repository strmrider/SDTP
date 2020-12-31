import struct, socket
from . import ca_consts
from .. import socket_wrapper as sw
from Crypto.Cipher import PKCS1_OAEP

class ClientCredentials:
    def __init__(self, client_id, password, public_key):
        self.id = client_id
        self.password = password
        self.public_key = public_key

class CAClient:
    def __init__(self, credentials, ca_public_key):
        self.__credentials = credentials
        self.__ca_public_key = ca_public_key
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__network = None

    def run(self, ip, port):
        self.__socket.connect((ip, port))
        self.__network = sw.Wrapper(self.__socket)
        try:
            self.__request_certificate()
            return self.__handle_response()
        except Exception as e:
            print(e)
            return None

    def __request_certificate(self):
        """
        Build and send certificate from Certificate Authority server
        """
        cipher = PKCS1_OAEP.new(self.__ca_public_key)
        cipher_id = cipher.encrypt(self.__credentials.id.encode('utf-8'))
        cipher_password = cipher.encrypt(self.__credentials.password.encode('utf-8'))
        public_key = self.__credentials.public_key.publickey().export_key()
        header = struct.pack("! B B I I I", 13, ca_consts.REQUEST_CERTIFICATE,
                              len(cipher_id), len(cipher_password), len(public_key))
        pack = bytearray(header + cipher_id + cipher_password + public_key)
        self.__network.send(pack)

    def __unpack_certificate(self, header):
        cert_len, signature_len = struct.unpack("!x I I", header)
        serialized_cert = self.__network.receive(cert_len)
        signature = self.__network.receive(signature_len)
        return {"certificate": serialized_cert, "signature": signature}

    def __handle_response(self):
        """
        Receives certificate request response
        """
        header = self.__network.read_header()
        response = struct.unpack("!B", header[:1])[0]
        if response == ca_consts.CERTIFICATE_GRANTED:
            return self.__unpack_certificate(header)
        elif response == ca_consts.CERTIFICATE_DENIED:
            raise Exception("Certification request denied")

        return None
