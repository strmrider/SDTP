import struct, socket, threading, datetime, pickle
from . import ca_consts
from ..sock import  Wrapper, NonBlockingSocket
from .models import database as db
from .models import client as db_client
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from Crypto.PublicKey import RSA

def generate_key(key_size):
    """
    Generates public and private keys per given key size
    :param key_size: int; cipher key size
    :return: bytes; key
    """
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("key/private.pem", "wb+") as private_file:
        private_file.write(private_key)
    with open("key/public.pem", "wb+") as public_file:
        public_file.write(public_key)

    return key

def read_key(path):
    """
    Reads key from file
    :param path: str; path to file
    :return: bytes; key
    """
    with open(path, "rb") as k_file:
        key = RSA.import_key(k_file.read())
    return key

def create_client(_id, password, key=None):
    """
    Crates a CA server client
    :param _id: str; client's id
    :param password: str; client's password
    :param key: bytes or None; public key
    :return: Client
    """
    return db_client.Client(_id, SHA256.new(password.encode("utf-8")).digest(), True, key, None)

class CAServer:
    """
    Certificate Authority Server.
    * Manages clients database
    * Receives certificate requests
    * verifies requests, signs and grants certificates
    Note:
    * Clients have to be registered manually to the server's database in advance in order to be
      recognized and verified during the request.
    * Anyone who wishes to verify certificates granted by the CA server must know the up to date
      CA server public key in advance
    """
    def __init__(self, ip, port, key):
        """
        :param ip: str; server's ip address
        :param port: int; server's port number
        :param key: bytes; server's private and public key pair
        """
        self.__private_key = self.__public_key = None
        self.set_keys(key)
        self.__database = db.Database()
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__bind(ip, port)
        self.__is_running = False

    def get_database(self):
        """
        Returns database
        :return: Database
        """
        return self.__database

    def set_keys(self, key):
        """
        Sets Server's public and private keys
        """
        self.__private_key = key
        self.__public_key = key.publickey()

    def __bind(self, ip, port):
        """
        Binds socket
        :param ip: str;
        :param port: int;
        """
        try:
            self.__socket.bind((ip, port))
            self.__socket.listen(5)
        except socket.error as e:
            print (e)

    def start(self):
        """
        Starts listening to connections
        """
        self.__is_running = True
        threading.Thread(target=self.__accept_connections).start()

    def stop(self):
        """
        Stops server
        """
        self.__is_running = False

    def close(self):
        """
        Closes the server and the socket
        """
        if self.__is_running:
            self.stop()
        self.__socket.close()

    def __accept_connections(self):
        """
        Accepts new connections
        """
        wrap = NonBlockingSocket(self.__socket)
        while self.__is_running:
            wrap.select()
            if wrap.is_readable():
                connection, addr = self.__socket.accept()
                print(addr)
                # handles new requests
                threading.Thread(target=self.__handle_certificate_request, args=(Wrapper(connection),)).start()

    def __handle_certificate_request(self, network):
        """
        Processes certificate request from a client, by verifying the client and granting the certificate
        :param network: Wrapper; socket wrapper
        :return: None
        """
        cipher = PKCS1_OAEP.new(self.__private_key)
        header = network.read_header()
        id_len, password_len, key_len = struct.unpack("! x I I I", header)
        client_id = (cipher.decrypt(network.receive(id_len))).decode("utf-8")
        password = (cipher.decrypt(network.receive(password_len))).decode("utf-8")
        public_key = network.receive(key_len)
        client = self.__database.get(client_id)
        if client and self.__database.verify_client(client.id, password):
            self.__grant_certificate(client.id, public_key, network)
        else:
            network.send(struct.pack("!B B", 1, ca_consts.CERTIFICATE_DENIED))

    def __grant_certificate(self, client_id, client_public_key, network):
        """
        Creates a certificate and sends it back to the client
        :param client_id: str; client's id
        :param client_public_key: bytes; client's public key
        :param network: Wrapper
        :return: None
        """
        current = datetime.datetime.now()
        validity = (current, current + datetime.timedelta(days=5))
        self.__database.get(client_id).validity = validity
        serialized_cert = pickle.dumps((client_id, client_public_key, validity))
        h = SHA256.new(serialized_cert)
        signature = pss.new(self.__private_key).sign(h)
        header = struct.pack("!B B I I", 9, ca_consts.CERTIFICATE_GRANTED,
                             len(serialized_cert), len(signature))
        pack = bytearray(header + serialized_cert + signature)
        network.send(pack)
