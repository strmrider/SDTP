import struct, pickle, datetime
from . import constants
from .ca.caclient import ClientCredentials, CAClient
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pss

__INT_SIZE = 4

def generate_rsa_keys(size):
    """
    Returns RSA keys
    :param size: int; key size
    """
    return RSA.generate(size)

def read_key(path):
    """
    Reads RSA keys from file
    :param path: str; file's path
    :return: RSA key
    """
    with open(path, "rb") as k_file:
        key = RSA.import_key(k_file.read())
    return key

"""
 The protocol uses hybrid encryption with both RSA and AES encryption algorithms.
 During the handshake the client and the server perform keys exchange with the server's public key
 and client's generated symmetric key (encrypted with the server's key)
"""

def request_certificate(cert_id, password, key, ca_public_key, server_credentials):
    """
    Requests certificate from CA server.
    :param cert_id: str; certification id
    :param password: str; client server password
    :param key: RSA public key; server's public key
    :param ca_public_key: bytes; CA server's pyublic key
    :param server_credentials: tuple(str, int); CA server ip address and port number
    :return: Certificate; CA server signed certificate in case client server is registered
    """
    credentials = ClientCredentials(cert_id, password, key)
    client = CAClient(credentials, ca_public_key)
    return client.run(server_credentials[0], server_credentials[1])

def __send_symmetric_key(network, symmetric_key, server_public_key):
    """
    Sends client's symmetric key to server (Part of the handshake process)
    :param network: Wrapper; socket wrapper
    :param symmetric_key: bytes; client's generate key
    :param server_public_key: server's public for the encryption of the symmetric key
    """
    cipher = PKCS1_OAEP.new(server_public_key)
    cipher_key = cipher.encrypt(symmetric_key)
    key_len = struct.pack("!B B I", 5, constants.SEND_SESSION_KEY, len(cipher_key))
    data = bytearray(key_len + cipher_key)
    network.send(data)

def __receive_symmetric_key(network, private_key):
    """
    Receives client's symmetric key (part of the handshake process)
    :param network: Wrapper; socket wrapper
    :param private_key: RSA private key; server's private key, used to decrypt the symmetric key
    :return: bytes; client's symmetric key
    """
    header = network.read_header()
    action, key_len = struct.unpack("!B I", header)
    if action == constants.SEND_SESSION_KEY:
        cipher_key = network.receive(key_len)
        cipher = PKCS1_OAEP.new(private_key)
        symmetric_key = cipher.decrypt(cipher_key)

        return symmetric_key

def __verify_cert_signature(certificate, signature, ca_key):
    """
    Verifies certificate signature
    :param certificate: Certificate; The certificate granted by the CA server
    :param signature: bytes; CA server's digital signature
    :param ca_key: RSa public key; CA server's public key
    :return: bool
    """
    h = SHA256.new(certificate)
    try:
        pss.new(ca_key).verify(h, signature)
        return True
    except Exception as e:
        print (e)
        return False

"""
 Handshake with certificate

 Handling connections establishment while using third party Certification Authority server.
 * The Server requests signature from CA server
 * The CA server verifies the server's data and send a certificate with its signature
 * The client verifies CA server signature
 * Client generates a symmetric key and send it to the server
"""

def read_certification(network):
    """
    Reads received certificate and returns its data
    :param network: Warpper; socket wrapper
    :return: tuple (bytes, dict); CA server signature and certificate data
    """
    header = network.read_header()
    cert_len, signature_len = struct.unpack("!x I I", header)
    cert_data = network.receive(cert_len)
    signature = network.receive(signature_len)

    return signature, cert_data

def server_handshake_cert(private_key, network, cert):
    """
    Establish Server side connection with a client with a certificate
    :param private_key: RAS private key; Server's private key
    :param network: Wrapper;
    :param cert: Certificate; Certificate provided and signed by the CA server
    :return: None or bytes; returns received generated symmetric key by client in case certificate was verified
    """
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
    """
    Establish client side connection with server using a certificate.
    Raises exception if certificate is invalid. In this case the establishment will fail and will be terminated.
    :param symmetric_key: bytes; generated AES cipher key
    :param network: Wrapper; socket wrapper
    :param ca_public_key: RSA public key; CA server public key
    """
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

"""
 Regular handshake
 Handling regular connections establishment with no certificate requirements (just keys exchange)
"""

def server_handshake(rsa_key, network):
    """
    Server's side connection establishment
    :param rsa_key: RSA key; sever's RSA key pair
    :param network: Wrapper; socket wrapper
    :return: bytes; client's symmetric key
    """
    public_key = rsa_key.publickey().export_key()
    pack_public_key = struct.pack("! I", len(public_key))
    network.send(bytearray(pack_public_key) + public_key)

    return __receive_symmetric_key(network, rsa_key)

def client_handshake(network, symmetric_key):
    """
    Establishes client side connection
    :param network: Wrapper; socket wrapper
    :param symmetric_key: bytes; client's symmetric key
    """
    public_key_len = struct.unpack("!I",  network.receive(__INT_SIZE))[0]
    public_key = RSA.importKey(network.receive(public_key_len))
    __send_symmetric_key(network, symmetric_key, public_key)