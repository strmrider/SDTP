import socket, os, threading
from .. import session_handler

NO_CERT = 0
CERT_VER = 1
DEFAULT_KEY_SIZE = 16

class BaseClient:
    def __init__(self):
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__wrapper = None
        self.__mode = NO_CERT
        self.__ca_public_key = None
        self.__session = None
        self.__session_key = os.urandom(DEFAULT_KEY_SIZE)
        self.__non_block_mode = False

    def set_cert_mode(self, ca_public_key):
        self.__ca_public_key = ca_public_key
        self.__mode = CERT_VER

    def connect(self, ip, port):
        self.__socket.connect((ip, port))
        self.__wrapper = session_handler.wrap(self.__socket)
        if self.__mode == NO_CERT:
            session_handler.client_handshake(self.__wrapper, self.__session_key)
        elif self.__mode == CERT_VER:
            if self.__ca_public_key:
                session_handler.client_handshake_cert(self.__session_key, self.__wrapper, self.__ca_public_key)
            else:
                raise Exception("Certificate authority server's public key is not provided")

        self.__session = session_handler.SessionHandler(self.__wrapper, self.__session_key)

    def get_session(self):
        return self.__session

    def get_wrapper(self):
        return self.__wrapper

    def non_blocking_connection(self):
        self.__non_block_mode = True
        threading.Thread(target=self.__non_blocking_connection).start()

    def stop_non_block_socket(self):
        self.__non_block_mode = False

    def __non_blocking_connection(self):
        self.__wrapper.set_non_blocking()
        while self.__non_block_mode:
            self.__wrapper.get_non_blocking().select()
            if self.__wrapper.get_non_blocking().is_readable():
                print(self.__session.receive())
            if self.__wrapper.get_non_blocking().is_writeable():
                self.__wrapper.send_from_queue()
