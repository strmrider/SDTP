import socket, threading, traceback
import struct
import uuid
import os
from Crypto.PublicKey import RSA
from ..handshake import generate_rsa_keys, _send_symmetric_key, _receive_symmetric_key
from ..sock import Wrapper
from ..session import Session


CREATE = 0
JOIN = 1
APPROVE = 2
FAILED = 3


class Node:
    """
    Represents a node in the network
    """
    def __init__(self, _id: str, connection, public_key):
        """
        :param _id: str; Node's unique id
        :param connection: Wrapper; client's connection
        :param public_key: PublicKey; client's RSA public key
        """
        self.id = _id
        self.sock = connection
        self.public_key = public_key

    def send(self, data):
        """
        Sends data to node
        :param data: bytes;
        """
        self.sock.send(data)


class Network:
    """
    Network of nodes
    """
    def __init__(self, name: str, encryption_key: RSA):
        """
        :param name: str; Network's name
        :param encryption_key: RSA; RSA keys pair
        """
        self.name = name
        self.encryption_key = encryption_key
        self.nodes = []

    def add_node(self, node: Node):
        """
        Adds new node to network
        :param node: Node
        """
        self.nodes.append(node)

    def broadcast(self, node_id: str, data: bytes):
        """
        Broadcasts data to all nodes in the network
        :param node_id: str; id of the sender
        :param data: bytes; the data to be sent
        """
        for node in self.nodes:
            if node.id != node_id:
                node.send(data)

'''
Note: In order to grant the users full control over their I/O streams during sessions, the server keeps the session key
stored on it, so it won't interfere your own made higher level protocols when updating the key or sending it to new 
nodes. If you wish that the server won't be aware of the key then you will have to implement your own key distribution 
and update methods (or even your own made network hub protocol, which would probably be more appropriate to your 
designated application anyway).
In case this security manner is not an issue or you are the operators of the server anyway, this service is suffice.
'''


class NetworkClient:
    def __init__(self):
        self.__connection = None
        self.session = None
        self.keys = generate_rsa_keys(1024)
        self.encryption_key = None

    def connect(self, ip, port):
        """
        Connects to the network server
        :param ip: str; server's ip
        :param port: int; server's port
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        self.__connection = Wrapper(sock)

    def __network(self, network_name: str, action):
        if action not in range(CREATE, JOIN+1):
            raise Exception('Invalid action')
        else:
            pack = struct.pack('! B B B', 2, action, len(network_name))
            pack = bytearray(pack + network_name.encode())
            self.__connection.send(pack)

            response = self.__connection.receive(1)
            response = struct.unpack('!B', response)[0]
            return response

    def join_network(self, network_name: str):
        """
        Adds new node to the network
        :param network_name: str;
        """
        response = self.__network(network_name, JOIN)
        if response == APPROVE:
            pk_len = len(self.keys.publickey().export_key())
            self.__connection.send(struct.pack('!I', pk_len))
            self.__connection.send(self.keys.publickey().export_key())
            self.encryption_key = _receive_symmetric_key(self.__connection, self.keys)
            self.session = Session(self.__connection, self.encryption_key)

    def create_network(self, network_name: str):
        """
        Creates new network. Raises an exception if creation failed
        :param network_name: str;
        """
        response = self.__network(network_name, CREATE)
        if response == APPROVE:
            self.encryption_key = os.urandom(16)
            size = struct.unpack('!I', self.__connection.receive(4))[0]
            server_public_key = self.__connection.receive(size)
            _send_symmetric_key(self.__connection, self.encryption_key, RSA.importKey(server_public_key))
            self.session = Session(self.__connection, self.encryption_key)
        else:
            raise Exception('Network not created')


class NetworkServer:
    """
    Network server. Managing the networks and broadcasts income data.
    """
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.networks = {}
        self.keys = generate_rsa_keys(1024)
        network = Network('test', os.urandom(16))
        self.networks['test'] = network

    def start(self, ip, port):
        """
        Starts the server
        :param ip: str; server's ip
        :param port: int; server's port
        """
        self.socket.bind((ip, port))
        self.socket.listen(5)
        print('listening...')
        while True:
            conn, addr = self.socket.accept()
            print(addr)
            threading.Thread(target=self.handle_client, args=(conn,)).start()

    def handle_creation(self, node, network_name, connection):
        """
        Handles new network creation
        :param node: Node; creator Node
        :param network_name: str' new network's name
        :param connection: Wrapper;
        """
        pk = self.keys.publickey().export_key()
        size = struct.pack('!I', len(pk))
        connection.send(bytearray(size + pk))
        symmetric_key = _receive_symmetric_key(connection, self.keys)
        network = Network(network_name, symmetric_key)
        network.add_node(node)
        self.networks[network_name] = network

        return network

    def handle_join(self, connection, node, network_name):
        """
        Handles new nodes in a network
        :param connection: Wrapper; node's connection
        :param node: Node; new node
        :param network_name: str;
        :return: Network; the network to joined to
        """
        network = self.networks[network_name]
        size = struct.unpack('!I', connection.receive(4))[0]
        public_key = connection.receive(size)
        _send_symmetric_key(connection, network.encryption_key, RSA.importKey(public_key))
        network.add_node(node)

        return network

    def handle_client(self, connection):
        """
        Handles new client
        :param connection: Socket; client's socket object
        """
        connection = Wrapper(connection)
        network = None
        try:
            header = connection.read_header()
            command, name_len = struct.unpack('! B B', header)
            name = connection.receive(name_len)
            name = name.decode('utf-8')
            _id = str(uuid.uuid4()).replace('-', ' ')
            node = Node(_id, connection, None)
            if command == CREATE:
                if name not in self.networks:
                    connection.send(struct.pack('!B', APPROVE))
                    network = self.handle_creation(node, name, connection)
                else:
                    connection.send(struct.pack('!B', FAILED))
            elif command == JOIN:
                if name in self.networks:
                    connection.send(struct.pack('!B', APPROVE))
                    network = self.handle_join(connection, node, name)
                else:
                    connection.send(struct.pack('!B', FAILED))
            if network:
                while True:
                    # use socket object directly
                    data = connection.connection.recv(1024)
                    if data:
                        network.broadcast(_id, data)
        except Exception as e:
            traceback.print_exception(type(e), e, e.__traceback__)
