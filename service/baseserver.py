import socket, threading, traceback
from .. import session_handler, socket_wrapper

NO_CERT = 0
CERT_VER = 1
DEFAULT_RSA_KEY_SIZE = 1024


class BaseServer:
    def __init__(self, ras_key=None):
        self.__set_keys(ras_key)
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__handshake_mode = NO_CERT
        self.__certificate = None
        self.__bind = False
        self.__lock = threading.Lock()

    def __set_keys(self, rsa_key):
        if rsa_key:
            self.__private_key = rsa_key
            self.__public_key = rsa_key.publickey()
        else:
            key = session_handler.generate_rsa_keys(DEFAULT_RSA_KEY_SIZE)
            self.__private_key = key
            self.__public_key = key.publickey()

    def set_cert_mode(self, certificate):
        self.__handshake_mode = CERT_VER if certificate else NO_CERT
        self.__certificate = certificate

    def start(self, ip, port, non_blocked=False):
        self.__socket.bind((ip, port))
        self.__socket.listen(5)
        self.__bind = True
        if non_blocked:
            self.__non_blocked_bind()
        else:
            while self.__bind:
                self.__accept_connections()

    def stop_bind(self):
        with self.__lock:
            self.__bind = False

    def __accept_connections(self):
        connection, address = self.__socket.accept()
        # print(address)
        threading.Thread(target=self.__handle_client, args=(connection,)).start()

    def __non_blocked_bind(self):
        wrap = socket_wrapper.NonBlockingSocket(self.__socket)
        while self.__bind:
            wrap.select()
            if wrap.is_readable():
                self.__accept_connections()

    def __handle_client(self, connection):
        network = session_handler.wrap(connection)
        session_key = None
        try:
            if self.__handshake_mode == NO_CERT:
                session_key = session_handler.server_handshake(self.__private_key, network)
            elif self.__handshake_mode == CERT_VER:
                session_key = session_handler.server_handshake_cert(self.__private_key, network, self.__certificate)

            session = session_handler.SessionHandler(network, session_key)
            self.handle_session(session)
        except Exception as e:
            traceback.print_exception(type(e), e, e.__traceback__)

    # after the session is established, this method will use the session in anyway you want it
    @staticmethod
    def __handle_session(session):
        pass
