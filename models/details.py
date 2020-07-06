class UserDetails:
    def __init__(self):
        self.id = None
        self.name = None
        self.certificate = None
        self.decryptor = None


class CAServerDetails:
    def __init__(self, ip, port, public_key):
        self.ip = ip
        self.port = port
        self.public_key = public_key
