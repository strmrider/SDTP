import constants


class Bytes:
    def __init__(self, data):
        self.type = constants.BYTES
        self.data = data

    def length(self):
        return len(self.data)

    def get_data(self):
        return self.data


class Text:
    def __init__(self, text):
        self.type = constants.TEXT
        self.text = text

    def length(self):
        return len(self.text)

    def get_text(self):
        return self.text


class File:
    def __init__(self, name, size, data):
        self.type = constants.FILE
        self.name = name
        self.size = size
        self.data = data

    def save(self, path=None):
        if not path:
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.name)
        with open(path, 'wb') as f:
            f.write(self.data)

    def get_data(self):
        return self.data

    def get_name(self):
        return self.name

    def get_size(self):
        return self.size

    def get_extension(self):
        tokens = self.filename.split('.')
        return tokens[len(tokens)-1]
