from Crypto.Hash import SHA256
import datetime

class Client:
    """
    CA server's registered client
    """
    def __init__(self, client_id, password, is_active, key, validity, access_time=None):
        """
        :param client_id: str; client's id
        :param password: bytes; client's hashed password
        :param is_active: boo; whether client's is active
        :param key: bytes; recent client's public key
        :param validity: bool; whether client's certificate is valid
        :param access_time: datetime; recent time client's data was accessed in database
                            (current time if not provided any)
        """
        self.id = client_id
        self.is_active = is_active
        self.password_hash = password
        self.recent_public_key = key
        self.access_time = access_time if access_time else datetime.datetime.now()
        self.validity = validity

    def compare_password(self, password):
        """
        Validates if given password's hash is equal to client's
        :param password: str
        :return: bool
        """
        return SHA256.new(password.encode("utf-8")).digest() == self.password_hash

    def update_access_time(self):
        """
        Update last access time
        """
        self.access_time = datetime.datetime.now()

    def serialize(self):
        """
        Serializes the client'd data
        :return: dict
        """
        return {"id": self.id,
                "password": self.password_hash,
                'active': self.is_active,
                "recentKey": self.recent_public_key,
                "validity": self.validity,
                "access": self.access_time
                }

    def get_values(self):
        """
        Returns all client's data values
        :return: list
        """
        active = "Active" if self.is_active else "Inactive"
        valid = "Invalid" if not self.validity else self.validity[0].strftime('%d/%m/%y %H:%M:%S')
        return [self.id, active, self.recent_public_key, valid, self.access_time]
