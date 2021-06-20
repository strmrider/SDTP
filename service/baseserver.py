import socket, threading, traceback
from .. import handshake, session, sock

NO_CERT = 0
CERT_VER = 1
DEFAULT_RSA_KEY_SIZE = 1024


class BaseServer:
    def __init__(self, rsa_key=None):
        self.__set_keys(rsa_key)
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__handshake_mode = NO_CERT
        self.__certificate = None
        self.__run = False
        self.__lock = threading.Lock()
        self.__non_block = False

        self.handler = None

    def __set_keys(self, rsa_key):
        if rsa_key:
            self.__private_key = rsa_key
            self.__public_key = rsa_key.publickey()
        else:
            key = handshake.generate_rsa_keys(DEFAULT_RSA_KEY_SIZE)
            self.__private_key = key
            self.__public_key = key.publickey()

    def set_cert_mode(self, certificate):
        self.__handshake_mode = CERT_VER if certificate else NO_CERT
        self.__certificate = certificate

    def start(self, ip, port, non_blocked=False):
        self.__socket.bind((ip, port))
        self.__socket.listen(5)
        self.__run = True
        print ("listening...")
        if non_blocked:
            self.__non_blocked_listen()
        else:
            while self.__run:
                self.__accept_connections()

    def stop(self):
        with self.__lock:
            self.__run = False

    def __accept_connections(self):
        connection, address = self.__socket.accept()
        print ("connection from ", address)
        threading.Thread(target=self.__handle_client, args=(connection,)).start()

    def __non_blocked_listen(self):
        self.__non_block = True
        wrap = sock.NonBlockingSocket(self.__socket)
        while self.__run:
            wrap.select()
            if wrap.is_readable():
                self.__accept_connections()

    def __handle_client(self, connection):
        network = sock.Wrapper(connection)
        session_key = None
        try:
            if self.__handshake_mode == NO_CERT:
                session_key = handshake.server_handshake(self.__private_key, network)
            elif self.__handshake_mode == CERT_VER:
                session_key = handshake.server_handshake_cert(self.__private_key, network, self.__certificate)

            _session = session.Session(network, session_key)
            self.handle_session(_session)
        except Exception as e:
            traceback.print_exception(type(e), e, e.__traceback__)

    # after the session is established, this method will use the session in anyway you want it
    def handle_session(self, session):
        if self.handler:
            self.handler(session)
