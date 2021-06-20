import socket, threading, struct, uuid
from ..baseclient import BaseClient

def send_target_info(ip, port, sock):
    """
    Sends target's server data to the VPN client
    :param ip: str; client's id
    :param port: str; target's server ip address
    :param sock: socket
    """
    data = struct.pack("! 4s I", socket.inet_aton(ip), port)
    sock.sendall(data)

def get_connection_header(_id, ip, port):
    """
    Returns connection request to the VPN server
    :param _id: str; client's id
    :param ip: str; target's server ip address
    :param port: int; target's server port number
    :return: dict;
    """
    return {'action': 'connection', 'id':_id, 'ip': ip, 'port': port}

class VPNClient:
    """
    The client runs on local machine and handles data transfer with the VPN server
    """
    def __init__(self, port):
        """
        :param port: int; port number
        """
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__vpn_server = BaseClient()
        self.__clients = {}
        self.__vpn_session = None
        self.port = port

    def run(self, vpn_ip, vpn_port):
        """
        Connects to VPN server
        :param vpn_ip: str; server's ip address
        :param vpn_port: int; server's port number
        """
        self.__vpn_server.connect(vpn_ip, vpn_port)
        self.__vpn_session = self.__vpn_server.get_session()
        threading.Thread(target=self.__listen_to_vpn, args=()).start()

        self.__socket.bind(('127.0.0.1', self.port))
        self.__socket.listen(5)
        while True:
            conn, address = self.__socket.accept()
            threading.Thread(target=self.__handle_client, args=(conn,)).start()

    def __listen_to_vpn(self):
        """
        Listens for income data from the user
        """
        while True:
            data = self.__vpn_session.receive().get_data()
            action = data['action']
            client = self.__clients[data['id']]
            if action == 'send':
                client['socket'].sendall(data['data'])
            elif action == 'close':
                client['status'] = False
                sock = client['socket']
                sock.shutdown(socket.SHUT_RD)
                sock.close()
                del self.__clients[data['id']]

    def __handle_client(self ,connection):
        """
        Handles connections between local sockets and the VPN server
        :param connection: socket;
        """
        _id = str(uuid.uuid4())
        self.__clients[_id] = {'socket': connection, 'status': True}
        # target server data from a local socket
        target_server = connection.recv(8)
        ip, port = struct.unpack("! 4s I", target_server)
        self.__vpn_session.send_object(get_connection_header(_id, socket.inet_ntoa(ip), port))
        while True:
            try:
                data = connection.recv(1024)
                if data:
                    self.__vpn_session.send_object({'action': 'send', 'id': _id, 'data': data})
            except Exception as e:
                print (e)
                if self.__clients[_id]['status']:
                    self.__vpn_session.send_object({'action': 'close', 'id': _id})
                break

