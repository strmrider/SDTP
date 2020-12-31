from Crypto.Hash import SHA256
import datetime

class Client:
    def __init__(self, client_id, password, is_active, key, validity, access_time=None):
        self.id = client_id
        self.is_active = is_active
        self.password_hash = password
        self.recent_public_key = key
        self.access_time = access_time if access_time else datetime.datetime.now()
        self.validity = validity

    def compare_password(self, password):
        return SHA256.new(password.encode("utf-8")).digest() == self.password_hash

    def update_access_time(self):
        self.access_time = datetime.datetime.now()

    def serialize(self):
        return {"id": self.id,
                "password": self.password_hash,
                'active': self.is_active,
                "recentKey": self.recent_public_key,
                "validity": self.validity,
                "access": self.access_time
                }

    def get_values(self):
        active = "Active" if self.is_active else "Inactive"
        valid = "Invalid" if not self.validity else self.validity[0].strftime('%d/%m/%y %H:%M:%S')
        return [self.id, active, self.recent_public_key, valid, self.access_time]
