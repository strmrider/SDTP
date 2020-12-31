import struct, select, queue

class NonBlockingSocket:
    """
    Socket connection that doesn't lock the main thread
    """
    def __init__(self, socket):
        self.__socket = socket
        self.__is_selecting = False
        self.__readable = self.__writeable = self.__exceptional = None

    def select(self):
        inputs = [self.__socket]
        self.__is_selecting = True
        self.__readable, self.__writeable, self.__exceptional = select.select(inputs, [self.__socket], inputs, 0)

    def quit_select(self):
        self.__is_selecting = False

    def is_readable(self):
        return self.__socket in self.__readable

    def is_writeable(self):
        return self.__socket in self.__writeable

    def is_exceptional(self):
        return self.__socket in self.__exceptional

    def is_selecting(self):
        return self.__is_selecting


class Wrapper:
    def __init__(self, connection):
        self.connection = connection
        self.__non_blocking = None
        self.__outgoing_data = queue.Queue()

    def read_header(self):
        length = self.receive(1)
        header_length = int(struct.unpack("!B", length)[0])
        header = self.receive(header_length)
        return header

    def set_non_blocking(self):
        self.__non_blocking = NonBlockingSocket(self.connection)

    def get_non_blocking(self):
        return self.__non_blocking

    def receive(self, data_size):
        data = self.connection.recv(data_size)
        if not data:
            raise Exception("Connection is lost")

        while len(data) < data_size:
            data += self.connection.recv(data_size - (len(data)))

        return data

    def send(self, data):
        if self.__non_blocking and self.__non_blocking.is_selecting():
            self.__outgoing_data.put(data)
        else:
            self.connection.sendall(data)

    def send_from_queue(self):
        if not self.__outgoing_data.empty():
            self.connection.sendall(self.__outgoing_data.get_nowait())

    def close(self):
        self.connection.close()