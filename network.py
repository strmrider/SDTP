import socket
import struct

NO_DATA = -1


class Network:
    def __init__(self, connection):
        self.connection = connection

    def read_header(self):
        length = self.connection.recv(1)
        if not length:
            raise Exception("Connection is lost")

        header_length = int(struct.unpack("!B", length)[0])
        header = self.receive(header_length)

        return header

    def read_number(self, size):
        number = self.connection.recv(size)
        return number

    def receive(self, data_size):
        data = self.connection.recv(data_size)
        if data == "":
            raise Exception("Connection is lost")

        while len(data) < data_size:
            data += self.connection.recv(data_size - (len(data)))

        return data

    def send(self, data):
        self.connection.sendall(data)

    def close(self):
        self.connection.close()
