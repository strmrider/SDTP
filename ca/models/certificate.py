from Crypto.Signature import pss
from Crypto.Hash import SHA256
import datetime

class Certificate:
    """
    Certification authority certificate. Client Servers must be registered to a CA server in order to obtain it.
    Contains CA sever's signature and verified by clients copy of CA server's public key.
    """
    def __init__(self, client_id, public_key, validity):
        """
        :param client_id: str; Client server's id registered in CA server
        :param public_key: bytes; CA server public key for verification
        :param validity: bool; whether certificate is valid
        """
        self.id = client_id
        self.public_key = public_key
        self.__validity = validity

    def verify(self, key):
        """
        Verifies signature
        :param key:
        :return: bool
        """
        h = SHA256.new(self.public_key.export_key())
        try:
             pss.new(key).verify(h, self.__signature)
             return True
        except Exception:
            return False

    def export_public_key(self):
        """
        Returns public key
        :return: bytes
        """
        return self.public_key.export_key()

    def get_signature(self):
        """
        Returns signature
        :return: bytes
        """
        return self.__signature

    def check_validity(self):
        """
        Returns certificate date validity
        :return: bool
        """
        current = datetime.now()
        return self.__validity[0] <= current <= self.__validity[1]