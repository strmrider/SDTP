from Crypto.Signature import pss
from Crypto.Hash import SHA256
import datetime

class Certificate:
    def __init__(self, client_id, public_key, validity):
        self.id = client_id
        self.public_key = public_key
        self.__validity = validity

    def verify(self, key):
        h = SHA256.new(self.public_key.export_key())
        try:
             pss.new(key).verify(h, self.__signature)
             return True
        except Exception:
            return False

    def export_public_key(self):
        return self.public_key.export_key()

    def get_signature(self):
        return self.__signature

    def check_validity(self):
        current = datetime.now()
        return self.__validity[0] <= current <= self.__validity[1]