import socket, threading
from ..baseserver import BaseServer

class Node:
    """
    The node which the VPN server is connecting to
    """
    def __init__(self, ip, port, _id, src_emitter, close_con):
        """
        :param ip: str; ip address
        :param port: int; port number
        :param _id: str; node's id
        :param src_emitter: callback function; handles income data from the node by the source client
        :param close_con: callback function; handles disconnection
        """
        self.id = _id
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((ip, port))
        self.src_emitter = src_emitter
        self.close_connection = close_con
        self.run = True
        threading.Thread(target=self.__listen, args=()).start()

    def __listen(self):
        """
        Listens to income data and invokes the callback
        """
        while self.run:
            try:
                data = self.socket.recv(1024)
                self.src_emitter(self.id, data)
            except Exception as e:
                print (e)
                print ('Connection with target node is lost')
                self.run = False
                self.close_connection(self.id)

    def send(self, data):
        """
        Sends data to node
        :param data: bytes
        """
        self.socket.sendall(data)

    def close(self):
        """
        Closes connection
        """
        self.run = False
        self.socket.shutdown(socket.SHUT_RD)
        self.socket.close()

class Client:
    """
    The client that requests the connection
    """
    def __init__(self, session):
        """
        :param session: Session; the session with the client
        """
        self.__session = session
        # contains all server's target nodes (servers). Nodes data is their ip address and port number
        self.__target_nodes = {}
        self.listen_to_client()

    def listen_to_client(self):
        """
        Listens to income data from the client and operates according to the requested actions.
        * connection - establish connection with a target server
        * send - send data to target server
        * close- close connection with target server
        """
        while True:
            request = self.__session.receive().get_data()
            action = request['action']
            # target server's id
            _id = request['id']
            if action == 'connection':
                self.__target_nodes[_id] = Node(request['ip'], request['port'], _id, self.send, self.close_connection)
            elif action == 'close':
                self.__target_nodes[_id].close()
                del self.__target_nodes[_id]
            elif action == 'send':
                self.__target_nodes[_id].send(request['data'])

    def send(self, _id, data):
        """
        Sends data to client
        :param _id: str; the server from which the data is sent
        :param data: bytes; sent data
        """
        self.__session.send_object({'action':'send', 'id':_id, 'data': data})

    def close_connection(self, _id):
        """
        Disconnect server node from client
        :param _id: str; server's id
        """
        self.__session.send_object({'action':'close', 'id': _id})

class VPNServer(BaseServer):
    """
    Listens to clients and links them to their requested node
    Establish connection with target servers and intermediate the data transfer.
    """
    def __init__(self, rsa_key=None):
        BaseServer.__init__(self, rsa_key)

    def handle_session(self, session):
        Client(session)
