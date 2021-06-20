import struct, ntpath, pickle, datetime, os
from . import constants, datatypes
from Crypto.Cipher import AES
import zlib

# all data transfer is accompanied by a header indicating the exact lengths to be read

# header size, type, compression, nonce length, mac length, data length
_BYTES_PACK_FORMAT = '! B B B I I I '
_BYTES_UNPACK_FORMAT = '! B B I I I'
_BYTES_HEADER_SIZE = 14
# header size, type, compression, filename nonce length, filename mac length,
# filename length, file nonce length, file mac length, file length
_FILE_PACK_FORMAT = '! B B B I I I I I I'
_FILE_UNPACK_FORMAT = '! B B I I I I I I'
_FILE_HEADER_SIZE = 26
# header size, type, nonce length, mac length, filename length
_FILE_HEADER_PACK = "! B B I I I"
_FILE_HEADER_UNPACK = "! x I I I"
_FILE_CHUNKS_HEADER_SIZE = 13
# header size, type, compression, data length
_OBJECT_PACK_FORMAT = "!B B B I"
_OBJECT_UNPACK_FORMAT = "!B B I"
_OBJECT_HEADER_SIZE = 6

class Session:
    """
    Server-client session
    """
    def __init__(self, network, session_key, compress_mode=False):
        """
        :param network: Wrapper; socket wrapper
        :param session_key: bytes; AES encryption key; The key to be used to encrypt traffic
        :param compress_mode: bool; True for traffic compression during transfer
        """
        # session's creation date
        self.timestamp = datetime.datetime
        self.__network = network
        self.__session_key = session_key
        self.__compress = compress_mode
        # files transfer options
        self.__file_autosave = False
        # max bytes on memory when handling files transfer
        self.__max_memory = 1024
        self.__files_target_dir = ''

    def set_autosave(self, status:bool):
        """
        Sets whether received files would be saved directly on disk or kept on memory
        :param status: bool
        """
        self.__file_autosave = status

    def max_memory(self, max_size):
        """
        Sets max data(bytes) on memory
        :param max_size: int
        """
        self.__max_memory = max_size

    def set_files_dir(self, directory:str):
        """
        Sets target directory to which files would be saved if requested
        :param directory: str;
        """
        self.__files_target_dir = directory

    def __encrypt(self, data):
        """
        Encrypts data and returns the cipher text, nonce and MAC
        :param data: bytes
        :return: tuple
        """
        cipher = AES.new(self.__session_key, AES.MODE_EAX)
        data = data.encode("utf-8") if isinstance(data, str) else data
        cipher_text, mac = cipher.encrypt_and_digest(data)
        return cipher_text, mac, cipher.nonce


    def __decrypt(self, data, tag, nonce):
        """
        Decrypts data and verifies it authentication. Raised exception if decryption process fails
        :param data: bytes; cipher data
        :param tag: bytes; signature
        :param nonce: bytes; used for better verification
        :return: None
        """
        cipher = AES.new(self.__session_key, AES.MODE_EAX, nonce)
        try:
            decrypted_data = cipher.decrypt(data)
            is_decrypted = True
        except Exception:
            raise Exception("Decryption failed")

        if is_decrypted:
            try:
                cipher.verify(tag)
                return decrypted_data
            except Exception:
                raise Exception("Verification failed")

    def receive(self):
        """
        Receives data from node (server or client)
        Note: Blocking function. Use non-blocking methods (such as NonBlockingSocket) to avoid it
        :return: DataType
        """
        header = self.__network.read_header()
        data_type = struct.unpack("!B", header[:1])[0]
        if data_type == constants.SEND_BYTES or data_type == constants.SEND_TEXT:
            return self.__unpack_bytes(header)
        elif data_type == constants.SEND_FILE:
            return self.__unpack_file(header)
        elif data_type == constants.SEND_COMPLETE_FILE:
            return self.__unpack_raw_file(header)
        elif data_type == constants.SEND_OBJECT or data_type == constants.SEND_LIST:
            return self.__unpack_object(header)

    """
    Handles text and raw bytes

    Raw bytes is the most basic and efficient procedure, and allows users to use their own serialization methods
    if required.
    Header size: 14 bytes
    Pack structure: header, nonce, mac, cipher data
    """

    def __unpack_bytes(self, header):
        """
        Dissects income data and returns Bytes or Text DataTypes
        :param header: bytes; pack's header segment
        :return: Bytes or Text;
        """
        type, is_compressed, nonce_len, mac_len, data_len = struct.unpack(_BYTES_UNPACK_FORMAT, header)
        nonce = self.__network.receive(nonce_len)
        mac = self.__network.receive(mac_len)
        data = self.__network.receive(data_len)
        data = self.__decrypt(data, mac, nonce)
        data = zlib.decompress(data) if is_compressed else data

        if type == constants.SEND_TEXT:
            return datatypes.Text(data)
        else:
            return datatypes.Bytes(data)

    def __send_bytes(self, data, action):
        """
        Builds and sends raw bytes data pack. Covers both bytes and text transfer as text is merely encoded bytes
        :param data: bytes; the data to be sent
        :param action: SEND_BYTES or SEND_TEXT
        """
        data = zlib.compress(data) if self.__compress else data
        cipher_data, mac, nonce = self.__encrypt(data)
        header = struct.pack(_BYTES_PACK_FORMAT, _BYTES_HEADER_SIZE,
                             action, self.__compress, len(nonce), len(mac), len(cipher_data))
        pack = bytearray(header + nonce + mac + cipher_data)

        self.__network.send(pack)

    def send_bytes(self, data):
        """
        Sends bytes
        :param data: bytes
        """
        self.__send_bytes(data, constants.SEND_BYTES)

    def send_text(self, text:str):
        """
        Sends text
        :param text: str
        """
        self.__send_bytes(text.encode('utf-8'), constants.SEND_TEXT)

    """
    Handles Files

    There are two possibilities to send files, both with there own advantage and disadvantage:
    1. Sending a complete file at once by loading all of it onto memory. Saves runtime but more expensive to memory.
       It's likely to be more efficient with relatively small sized files (depends on available RAM).
    2. Sending files in chunks. Saves memory space but could be more expensive to runtime due to many
       system calls to disk reading. The size of each chunk is defined by the `max_memory()` method.

    Files can also be received by those methods depends on the settings. If file auto-save is set on, received files
    would be written to disk - chunk by chunk or completely - depending on which method they are sent with.

    Note: Files are saved on local directory unless a new directory is set by the method `set_files_dir()`
    """

    def send_raw_file(self, filename:str, bin_file):
        """
        Sends complete file at once
        :param filename: str; original file name
        :param bin_file: bytes; file's content
        """
        bin_file = zlib.compress(bin_file) if self.__compress else bin_file
        cipher_filename, filename_mac, filename_nonce = self.__encrypt(filename)
        cipher_file, file_tag, file_nonce = self.__encrypt(bin_file)
        header = struct.pack(_FILE_PACK_FORMAT, _FILE_HEADER_SIZE, constants.SEND_COMPLETE_FILE, self.__compress,
                             len(filename_nonce), len(filename_mac), len(cipher_filename),
                             len(file_nonce), len(file_tag), len(cipher_file))
        pack = \
            bytearray(header + filename_nonce + filename_mac + cipher_filename + file_nonce + file_tag + cipher_file)

        self.__network.send(pack)

    def __unpack_raw_file(self, header):
        """
        Dissects complete file pack
        :param header: bytes; pack's header segment
        :return: File DataType; the file is encompassed in the DataTpe
        """
        components = struct.unpack(_FILE_UNPACK_FORMAT, header)
        is_compressed = self.__network.receive(components[1])
        filename_nonce = self.__network.receive(components[2])
        filename_tag = self.__network.receive(components[3])
        cipher_filename = self.__network.receive(components[4])

        file_nonce = self.__network.receive(components[5])
        file_tag = self.__network.receive(components[6])
        cipher_file = self.__network.receive(components[7])

        filename = self.__decrypt(cipher_filename, filename_tag, filename_nonce)
        file_data = self.__decrypt(cipher_file, file_tag, file_nonce)
        file_data = zlib.decompress(file_data) if is_compressed else file_data


        return datatypes.File(filename.decode("utf-8"), len(file_data), file_data, constants.FILE)


    def __pack_file_header(self, filename: str, total_size):
        """
        Builds file pack header segment
        :param filename: dtr; file name
        :param total_size: int; total file's size
        :return: bytes
        """
        file_header = pickle.dumps((filename, total_size))
        cipher_header, mac, nonce = self.__encrypt(file_header)
        header = struct.pack(_FILE_HEADER_PACK, _FILE_CHUNKS_HEADER_SIZE, constants.SEND_FILE,
                             len(nonce), len(mac), len(cipher_header))
        pack = bytearray(header + nonce + mac + cipher_header)

        return pack


    def __save_file_on_disk(self, filename, total_size):
        """
        Writes received file to disk and returns it as SavedFile DataType
        :param filename: str; file name
        :param total_size: int; total file's size
        :return: SavedFile
        """
        _file = open(filename, "wb+")
        total_received = 0
        while total_received < total_size:
            received_bytes = self.receive().get_data()
            total_received += (len(received_bytes))
            _file.write(received_bytes)

        return datatypes.SavedFile(filename, total_size)


    def __load_file_into_memory(self, filename, total_size):
        """
        Loads received file into memory method and returns its DataType
        :param filename: str; file name
        :param total_size:int; total file's size
        :return: File
        """
        data = bytearray()
        total_received = 0
        while total_received < total_size:
            received_bytes = self.receive().get_data()
            total_received += (len(received_bytes))
            data += received_bytes

        return datatypes.File(filename, total_size, data, constants.FILE)


    def __unpack_file(self, header):
        """
        Dissects received file pack
        :param header: bytes; pack's header segment
        :return: File or SavedFile; depends on the transfer method that is used
        """
        nonce_len, mac_len, cipher_header_len = struct.unpack(_FILE_HEADER_UNPACK, header)
        nonce = self.__network.receive(nonce_len)
        mac = self.__network.receive(mac_len)
        cipher_header = self.__network.receive(cipher_header_len)
        file_header = self.__decrypt(cipher_header, mac, nonce)
        filename, total_size = pickle.loads(file_header)

        if self.__file_autosave:
            return self.__save_file_to_disk(filename, total_size)
        else:
            return self.__load_file_to_memory(filename, total_size)

    def send_file(self, path:str):
        """
        Sends a file from disk in chunks avoiding loading all of it onto memory
        :param path: str; file's path
        """
        file_size = os.path.getsize(path)
        filename = ntpath.basename(path)
        with open(path, "rb") as _file:
            self.__network.send(self.__pack_file_header(filename, file_size))
            data = _file.read(self.__max_memory)
            while data:
                self.send_bytes(data)
                data = _file.read(self.__max_memory)

    """
    Serialized objects

    Supports dictionary, list and tuple data types. Very convenient, simple when sending complete objects.

    Note: The serialization is using 'pickle' module. Other serializations alternatives could be are more efficient,
          both in serialized values length and faster run time. For most cases this procedure may be suffice,
          in other cases it might be better to use alternatives and send the value normally as raw bytes.
    """

    def __pack_object(self, obj, send_type):
        """
        Builds and serializes a serialized object pack
        :param obj: dict, list, tuple; the object be packed
        :param send_type: SEND_LIST or SEND_OBJECT; type of object so the receiver will know to refer to the exact data type
        :return: bytearray; serialized object pack
        """
        serialized_object = pickle.dumps(obj)
        serialized_object = zlib.compress(serialized_object) if self.__compress else serialized_object
        cipher_object, mac, nonce = self.__encrypt(serialized_object)
        data = {"nonce": nonce, "mac": mac, "object": cipher_object}
        data = pickle.dumps(data)
        header = struct.pack(_OBJECT_PACK_FORMAT, _OBJECT_HEADER_SIZE, send_type, self.__compress, len(data))

        return bytearray(header + data)

    def __unpack_object(self, header):
        """
        Dissects serialized object pack
        :param header: bytes; pack's header segment
        :return: Object or List DataTypes
        """
        _type, is_compressed, data_len = struct.unpack(_OBJECT_UNPACK_FORMAT, header)
        data = self.__network.receive(data_len)
        data = pickle.loads(data)
        obj = self.__decrypt(data["object"], data["mac"], data["nonce"])
        obj = zlib.decompress(obj) if is_compressed else obj
        deserialized_object = pickle.loads(obj)
        if _type == constants.SEND_OBJECT:
            return datatypes.Object(deserialized_object)
        elif _type == constants.SEND_LIST:
            return datatypes.List(deserialized_object)

    def send_object(self, obj:dict):
        """
        Send a dictionary
        :param obj: dict
        """
        pack = self.__pack_object(obj, constants.SEND_OBJECT)
        self.__network.send(pack)

    def send_list(self, list_items:list):
        """
        Sends list or tuple
        :param list_items: list, tuple
        """
        pack = self.__pack_object(list_items, constants.SEND_LIST)
        self.__network.send(pack)
