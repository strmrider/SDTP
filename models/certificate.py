import struct
import constants


class Certificate:
    def __init__(self, name, key, signature):
        self.name = name
        self.key = key
        self.signature = signature

    def sign(self, signature):
        self.signature = signature

    def pack(self, pack_type):
        if self.signature:
            # converted from list of ords
            str_signature = ",".join(map(str, self.signature))
            header = struct.pack("! B B H I I I",
                                 15,
                                 pack_type,
                                 len(self.name),
                                 len(self.key[0]),
                                 len(self.key[1]),
                                 len(str_signature))
            full_pack = header + self.name + str(self.key[0]) + str(self.key[1]) + str_signature
            pack = bytearray(full_pack)

            return pack

        else:
            raise Exception("Cannot pack an unsigned certificate.")