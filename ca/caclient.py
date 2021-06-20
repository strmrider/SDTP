import struct, socket
from . import ca_consts
from .. import socket_wrapper as sw
from Crypto.Cipher import PKCS1_OAEP

class ClientCredentials:
    """
    Stores client credentials
    """
    def __init__(self, client_id, password, public_key):
        self.id = client_id
        self.password = password
        self.public_key = public_key

class CAClient:
    """
    CA server's client. Builds a certificate with its won credentials and requests the server to sign it.
    """
    def __init__(self, credentials, ca_public_key):
        """
        Client's credentials
        :param credentials: ClientCredentials;
        :param ca_public_key: bytes; CA server's public key
        """
        self.__credentials = credentials
        self.__ca_public_key = ca_public_key
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__network = None

    def run(self, ip, port):
        """
        Connects client to CA server and requests a certificate
        :param ip: str; CA server's ip address
        :param port: CA server's port number
        :return: None or Certificate; depends if request is successful
        """
        self.__socket.connect((ip, port))
        self.__network = sw.Wrapper(self.__socket)
        try:
            # certificate is granted
            self.__request_certificate()
            return self.__handle_response()
        # request error occurs
        except Exception as e:
            print(e)
            return None

    def __request_certificate(self):
        """
        Builds certificate request and send sit to CA server
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
        """
        Unpacks income granted certificate from server
        :param header: bytes; CA server's stream data's header section
        :return: dict; certificate and CA server's signature
        """
        cert_len, signature_len = struct.unpack("!x I I", header)
        serialized_cert = self.__network.receive(cert_len)
        signature = self.__network.receive(signature_len)
        return {"certificate": serialized_cert, "signature": signature}

    def __handle_response(self):
        """
        Receives certificate request response. Throws exception if an error occurs
        :return: Certificate or None; depends whether the certificate is successfully granted
        """
        header = self.__network.read_header()
        response = struct.unpack("!B", header[:1])[0]
        if response == ca_consts.CERTIFICATE_GRANTED:
            return self.__unpack_certificate(header)
        elif response == ca_consts.CERTIFICATE_DENIED:
            raise Exception("Certification request denied")

        return None
