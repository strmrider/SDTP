import struct, ntpath, pickle, datetime
from . import constants, datatypes, socket_wrapper
from .ca import caclient
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss

__INT_SIZE = 4

def wrap(connection):
    return socket_wrapper.Wrapper(connection)

def generate_rsa_keys(size):
    return RSA.generate(size)

def read_key(path):
    with open(path, "rb") as k_file:
        key = RSA.import_key(k_file.read())
    return key

def read_header(network):
    length = network.receive(1)
    header_length = int(struct.unpack("!B", length)[0])
    header = network.receive(header_length)

    return header

def request_certificate(cert_id, password, key, ca_public_key, server_credentials):
    credentials = caclient.ClientCredentials(cert_id, password, key)
    client = caclient.CAClient(credentials, ca_public_key)
    return client.run(server_credentials[0], server_credentials[1])

def __send_symmetric_key(network, symmetric_key, server_public_key):
    cipher = PKCS1_OAEP.new(server_public_key)
    cipher_key = cipher.encrypt(symmetric_key)
    key_len = struct.pack("!B B I", 5, constants.SEND_SESSION_KEY, len(cipher_key))
    data = bytearray(key_len + cipher_key)
    network.send(data)

def __receive_symmetric_key(network, private_key):
    header = network.read_header()
    action, key_len = struct.unpack("!B I", header)
    if action == constants.SEND_SESSION_KEY:
        cipher_key = network.receive(key_len)
        cipher = PKCS1_OAEP.new(private_key)
        symmetric_key = cipher.decrypt(cipher_key)

        return symmetric_key

def __verify_cert_signature(certificate, signature, ca_key):
    h = SHA256.new(certificate)
    try:
        pss.new(ca_key).verify(h, signature)
        return True
    except Exception as e:
        print (e)
        return False

#############################
# Handshake with certificate
#############################

def server_handshake_cert(private_key, network, cert):
    header = struct.pack("! B B I I", 9, constants.SEND_CERTIFICATE,
                                  len(cert["certificate"]), len(cert["signature"]))
    data = bytearray(header + cert["certificate"] + cert["signature"])
    network.send(data)
    response_header = network.read_header()
    response = struct.unpack("!B", response_header[:1])[0]
    if response == constants.CERT_FAILED:
        raise Exception("Client couldn't verify given certificate")
    elif response == constants.CERT_SUCCEEDED:
        return __receive_symmetric_key(network, private_key)
    else:
        return None

def client_handshake_cert(symmetric_key, network, ca_public_key):
    header = network.read_header()
    cert_len, signature_len = struct.unpack("!x I I", header)
    cert_data = network.receive(cert_len)
    signature = network.receive(signature_len)
    if __verify_cert_signature(cert_data, signature, ca_public_key):
        _id, public_key, validity = pickle.loads(cert_data)
        current = datetime.datetime.now()
        if validity[0] <= current <= validity[1]:
            network.send(bytearray(struct.pack("!B B", 1, constants.CERT_SUCCEEDED)))
            __send_symmetric_key(network, symmetric_key, RSA.importKey(public_key))
        else:
            network.send(bytearray(struct.pack("!B B", 1, constants.CERT_FAILED)))
            raise Exception("Certificate is outdated!")
    else:
        network.send(bytearray(struct.pack("!B B", 1, constants.CERT_FAILED)))
        raise Exception("Unauthorised certificate")

####################
# Regular handshake
####################

def server_handshake(rsa_key, network):
    public_key = rsa_key.publickey().export_key()
    pack_public_key = struct.pack("! I", len(public_key))
    network.send(bytearray(pack_public_key) + public_key)

    return __receive_symmetric_key(network, rsa_key)

def client_handshake(network, symmetric_key):
    public_key_len = struct.unpack("!I",  network.receive(__INT_SIZE))[0]
    public_key = RSA.importKey(network.receive(public_key_len))
    __send_symmetric_key(network, symmetric_key, public_key)


####################
# Session handler
####################

class SessionHandler:
    def __init__(self, network, session_key):
        self.__network = network
        self.__session_key = session_key

    def get_connection(self):
        return self.__network

    def __read_header(self):
        length = self.__network.receive(1)
        header_length = int(struct.unpack("!B", length)[0])
        header = self.__network.receive(header_length)
        return header
    
    def __encrypt(self, data):
        cipher = AES.new(self.__session_key, AES.MODE_EAX)
        data = data.encode("utf-8") if isinstance(data, str) else data
        cipher_text, tag = cipher.encrypt_and_digest(data)
        return cipher_text, tag, cipher.nonce

    def __decrypt(self, data, tag, nonce):
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
        header = self.__read_header()
        data_type = struct.unpack("!B", header[:1])[0]
        if data_type == constants.SEND_BYTES or data_type == constants.SEND_TEXT:
            return self.__unpack_bytes(header)
        elif data_type == constants.SEND_FILE:
            return self.__unpack_file(header)
        elif data_type == constants.SEND_OBJECT or data_type == constants.SEND_LIST:
            return self.__unpack_object(header)

    def __unpack_bytes(self, header):
        type, nonce_len, tag_len, data_len = struct.unpack("! B I I I", header)
        nonce = self.__network.receive(nonce_len)
        tag = self.__network.receive(tag_len)
        data = self.__network.receive(data_len)
        data = self.__decrypt(data, tag, nonce)
        if type == constants.SEND_TEXT:
            return datatypes.Text(data)
        else:
            return datatypes.Bytes(data)

    def __send_bytes(self, data, action):
        cipher_data, tag, nonce = self.__encrypt(data)
        header = struct.pack("! B B I I I", 13, action, len(nonce), len(tag), len(cipher_data))
        pack = bytearray(header + nonce + tag + cipher_data)
        self.__network.send(pack)

    def send_bytes(self, data):
        self.__send_bytes(data, constants.SEND_BYTES)

    def send_text(self, text:str):
        self.__send_bytes(text, constants.SEND_TEXT)

    def __unpack_file(self, header):
        components = struct.unpack("! B I I I I I I", header)
        filename_nonce = self.__network.receive(components[1])
        filename_tag = self.__network.receive(components[2])
        cipher_filename = self.__network.receive(components[3])
        file_nonce = self.__network.receive(components[4])
        file_tag = self.__network.receive(components[5])
        cipher_file = self.__network.receive(components[6])
        filename = self.__decrypt(cipher_filename, filename_tag, filename_nonce)
        file_data = self.__decrypt(cipher_file, file_tag, file_nonce)

        return datatypes.File(filename.decode("utf-8"), len(file_data), file_data)

    def send_file_from_path(self, path:str):
        filename = ntpath.basename(path)
        with open(path, "rb") as _file:
            data = _file.read()

        self.send_file(filename, data)

    def send_file(self, filename:str, data):
        cipher_filename, filename_tag, filename_nonce =  self.__encrypt(filename)
        cipher_file, file_tag, file_nonce = self.__encrypt(data)
        header = struct.pack("! B B I I I I I I", 25, constants.SEND_FILE,
                             len(filename_nonce), len(filename_tag), len(cipher_filename),
                             len(file_nonce), len(file_tag), len(cipher_file))
        pack = \
            bytearray(header + filename_nonce + filename_tag + cipher_filename + file_nonce + file_tag + cipher_file)
        self.__network.send(pack)

    def __unpack_object(self, header):
        _type, data_len = struct.unpack("!B I", header)
        data = self.__network.receive(data_len)
        data = pickle.loads(data)
        obj = self.__decrypt(data["object"], data["tag"], data["nonce"])
        deserialized_object = pickle.loads(obj)
        if _type == constants.SEND_OBJECT:
            return datatypes.Object(deserialized_object)
        elif _type == constants.SEND_LIST:
            return datatypes.List(deserialized_object)

    def __send_object(self, obj, send_type):
        serialized_object = pickle.dumps(obj)
        cipher_object, tag, nonce = self.__encrypt(serialized_object)
        data = {"nonce": nonce, "tag": tag, "object": cipher_object}
        data = pickle.dumps(data)
        header = struct.pack("!B B I", 5, send_type, len(data))
        self.__network.send(bytearray(header + data))

    def send_object(self, obj:dict):
        self.__send_object(obj, constants.SEND_OBJECT)

    def send_list(self, list_items:list):
        self.__send_object(list_items, constants.SEND_LIST)
