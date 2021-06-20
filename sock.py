import struct, select, queue, socket

class NonBlockingSocket:
    """
    Socket connection that doesn't block the main thread
    """
    def __init__(self, socket):
        """
        :param socket: Socket
        """
        self.__socket = socket
        self.__is_selecting = False
        self.__readable = self.__writeable = self.__exceptional = None

    def select(self):
        """
        Checks if hardware is available for socket read or write (running select method of 'select' module)
        """
        inputs = [self.__socket]
        self.__is_selecting = True
        self.__readable, self.__writeable, self.__exceptional = select.select(inputs, [self.__socket], inputs, 0)

    def quit_select(self):
        """
        Sets socket select mode to false
        """
        self.__is_selecting = False

    def is_readable(self):
        """
        Returns whether new data is available to socket
        :return: bool
        """
        return self.__socket in self.__readable

    def is_writeable(self):
        """
        Returns whether new data can be sent through socket
        :return: bool
        """
        return self.__socket in self.__writeable

    def is_exceptional(self):
        """
        Returns whether an error occurs during select running
        :return: bool
        """
        return self.__socket in self.__exceptional

    def is_selecting(self):
        """
        Returns whether select is on
        :return: bool
        """
        return self.__is_selecting


class Wrapper:
    """
    Socket wrapper for extended socket functions.
    """
    def __init__(self, connection):
        """
        :param connection: Socket; socket instance
        """
        self.connection = connection
        self.__non_blocking = None
        self.__outgoing_data = queue.Queue()

    def read_header(self):
        """
        Returns pack's header segment
        :return: bytes
        """
        length = self.receive(1)
        header_length = int(struct.unpack("!B", length)[0])
        header = self.receive(header_length)
        return header

    def set_non_blocking(self):
        """
        Sets non-blocking mode
        """
        self.__non_blocking = NonBlockingSocket(self.connection)

    def get_non_blocking(self):
        """
        Returns non blocking socket
        :return: NonBlockingSocket
        """
        return self.__non_blocking

    def receive(self, buffer):
        """
        Receives data through socket. The method keeps looking for income data from stream
        until all buffer are received.
        :param buffer: int; buffer length
        :return: bytes; received data from socket
        """
        data = self.connection.recv(buffer)
        if not data:
            raise Exception("Connection is lost")

        while len(data) < buffer:
            data += self.connection.recv(buffer - (len(data)))

        return data

    def send(self, data):
        """
        Sends data through socket
        :param data: bytes
        """
        if self.__non_blocking and self.__non_blocking.is_selecting():
            self.__outgoing_data.put(data)
        else:
            self.connection.sendall(data)

    def send_from_queue(self):
        """
        Used when blocking mode is active. All data is first accumulated in a queue and then sent when socket is writable
        """
        if not self.__outgoing_data.empty():
            self.connection.sendall(self.__outgoing_data.get_nowait())

    def close(self):
        """
        Closes connection
        """
        self.connection.shotdown(socket.SHUT_RDWR)
        self.connection.close()