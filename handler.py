import rsa.rsa as rsa
import struct
import constants
import models.data_types as data_types
import ca_server.ca_client as ca_server


def get_certificate_from_ca_server(user_id, name, ca_server_details, decryptor):
    try:
        certificate = ca_server.receive_certificate(user_id, name, ca_server_details.public_key, ca_server_details.ip,
                                                    ca_server_details.port, decryptor)
        print "Certification granted!"
        return certificate
    except Exception as e:
        print "Failed to grant certification: " + str(e)


class Handler:
    def __init__(self, network, decryptor, ca_public_key, certificate):
        self.network = network
        # own certificate
        self.certificate = certificate
        self.ca = rsa.Encryptor(ca_public_key[0], ca_public_key[1])
        self.decryptor = decryptor
        self.enctyptor = None
        self.client_name = None

    def handshake(self, mode):
        try:
            public_key = None
            if mode == constants.SERVER_HANDSHAKE:
                public_key = self.receive_certificate()
                self.send_certificate()
            elif mode == constants.CLIENT_HANDSHAKE:
                self.send_certificate()
                public_key = self.receive_certificate()
            if public_key:
                self.enctyptor = rsa.Encryptor(public_key[0], public_key[1])
        except Exception as e:
            raise e

    def send_certificate(self):
        self.network.send(self.certificate.pack(constants.CERTIFICATE_PRESENT))
        if not self.is_certificate_verified():
            raise Exception("Client failed to verify certificate")

    def receive_certificate(self):
        public_key = self.handle_income_certificate()
        if not public_key:
            raise Exception("Client is not certified")
        else:
            # sends verification approval
            self.network.send(struct.pack("! B B", 1, constants.CERTIFICATE_VERIFIED))
            return public_key

    def handle_income_certificate(self):
        header = self.network.read_header()
        components = struct.unpack("! B H I I I", header)
        if components[0] != constants.CERTIFICATE_PRESENT:
            return None
        name = self.network.receive(components[1])
        key_n = self.network.receive(components[2])
        key_e = self.network.receive(components[3])
        signature = self.network.receive(components[4])
        signature = map(long, signature.split(","))
        if self.ca.verify_signature(signature, str(key_e)):
            self.client_name = name
            return int(key_n), int(key_e)
        else:
            return None

    def is_certificate_verified(self):
        header = self.network.read_header()
        header = struct.unpack("!B", header)
        return header[0] == constants.CERTIFICATE_VERIFIED

    def unpack_bytes(self, header):
        components = struct.unpack("! B I I", header)
        signature = self.network.receive(components[1])
        signature = self.convert_rsa_output(signature, 2)

        data = self.network.receive(components[2])
        data = self.decrypt(data)

        if self.enctyptor.verify_signature(signature, data):
            return data_types.Bytes(bytes(data))
        else:
            raise Exception("Source is unverified")

    def unpack_text(self, header):
        try:
            bytes_pack = self.unpack_bytes(header)
            text = bytes_pack.data
            return data_types.Text(text)
        except Exception as e:
            raise e

    def unpack_file(self, header):
        components = struct.unpack("! B I I I", header)

        signature = self.network.receive(components[1])
        signature = self.convert_rsa_output(signature, 2)

        filename_len = self.network.receive(components[2])
        filename_len = int(self.decrypt(filename_len))

        data_len = self.network.receive(components[3])
        data_len = int(self.decrypt(data_len))

        filename = self.network.receive(filename_len)
        filename = self.decrypt(filename)

        data = self.network.receive(data_len)
        data = self.decrypt(data)

        if self.enctyptor.verify_signature(signature, data):
            return data_types.File(filename, components[3], data)
        else:
            raise Exception("Source is unverified")

    def receive(self):
        header = self.network.read_header()
        data_type = struct.unpack("!B", header[0])[0]
        if data_type == constants.SEND_BYTES:
            return self.unpack_bytes(header)
        elif data_type == constants.SEND_TEXT:
            return self.unpack_text(header)
        elif data_type == constants.SEND_FILE:
            return self.unpack_file(header)

    def send_bytes(self, data, task_type=None):
        if not task_type:
            task_type = constants.SEND_BYTES
        signature = self.decryptor.sign_message(data)
        signature = self.convert_rsa_output(signature, constants.RSA_TO_STR)

        encrypted_data = self.encrypt(data)
        header = struct.pack("! B B I I", 9, task_type, len(signature), len(encrypted_data))
        pack = bytearray(header + signature + encrypted_data)
        self.network.send(pack)

    def send_text(self, text):
        self.send_bytes(text, constants.SEND_TEXT)

    def send_file(self, filename, data):
        signature = self.decryptor.sign_message(data)
        signature = self.convert_rsa_output(signature, constants.RSA_TO_STR)

        filename_encryption = self.encrypt(filename)
        filename_len = self.encrypt(str(len(filename_encryption)))

        data_encryption = self.encrypt(data)
        data_len = self.encrypt(str(len(data_encryption)))

        header = struct.pack("! B B I I I", 13, constants.SEND_FILE, len(signature), len(filename_len), len(data_len))

        pack = bytearray(header + signature + filename_len + data_len + filename_encryption + data_encryption)
        self.network.send(pack)

    def encrypt(self, data):
        encryption = self.enctyptor.encrypt(data)
        return self.convert_rsa_output(encryption, constants.RSA_TO_STR)

    def decrypt(self, data):
        array = self.convert_rsa_output(data, constants.STR_TO_RSA)
        return self.decryptor.decrypt(array)

    @staticmethod
    def convert_rsa_output(data, mode):
        if mode == constants.RSA_TO_STR:
            return ",".join(map(str, data))
        elif mode == constants.STR_TO_RSA:
            return map(long, data.split(","))
