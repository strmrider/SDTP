import socket, threading, struct
from ..sock import NonBlockingSocket
from .baseclient import BaseClient

class ProxyClient(BaseClient):
    """
    Connects to a proxy server.
    """
    def __init__(self):
        BaseClient.__init__(self)
        self.__socket = self._BaseClient__socket

    def connect(self, proxy, target):
        """
        Connects to the proxy server
        :param proxy: tuple (str, int); proxy server's ip and port addresses
        :param target: tuple (str, int); target server's ip and port addresses
        """
        self.__socket.connect(proxy)
        # packs and sends target server addresses
        target_pack = struct.pack("! 4s I", socket.inet_aton(target[0]), target[1])
        self.__socket.sendall(target_pack)
        # runs BaseClient
        self._BaseClient__establish_connection()

class ProxyServer:
    """
    Connects two nodes on network.
    """
    def __init__(self):
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__run = False

    def run(self, ip, port):
        """
        Runs the server
        :param ip: str; server's ip address
        :param port: int; port address
        """
        self.__run = True
        self.__socket.bind((ip, port))
        self.__socket.listen(5)
        wrapped_socket = NonBlockingSocket(self.__socket)
        print ('listening...')
        while self.__run:
            wrapped_socket.select()
            if wrapped_socket.is_readable():
                connection, address = self.__socket.accept()
                threading.Thread(target=self.__handle_client, args=(connection,)).start()

    def __handle_client(self, client):
        """
        Connects client to it's server and delivers sent data between them
        :param client: socket; socket connection
        """
        target_server = client.recv(8)
        # target node's ip address and port number
        ip, port = struct.unpack("! 4s I", target_server)
        target_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_server.connect((socket.inet_ntoa(ip), port))
        threading.Thread(target=self.__connect_nodes, args=(client, target_server)).start()
        threading.Thread(target=self.__connect_nodes, args=(target_server, client)).start()

    def __connect_nodes(self, first_edge, second_edge):
        """
        Receives ands sends data from one node to the other
        :param first_edge: socket
        :param second_edge: socket
        """
        while True:
            try:
                income_data = first_edge.recv(1024)
                second_edge.sendall(income_data)
            except Exception as e:
                print (e)
                print('Connection lost')
                break


