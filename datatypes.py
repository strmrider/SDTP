from . import constants
import os

class DataType:
    def __init__(self, _type, data):
        self.__type = _type
        self.__data = data

    def get_type(self):
        return self.__type

    def get_data(self):
        return self.__data

class Bytes(DataType):
    def __init__(self, data):
        DataType.__init__(self, constants.BYTES, data)

    def length(self):
        return len(self.get_data())

class Text(DataType):
    def __init__(self, text):
        DataType.__init__(self, constants.TEXT, text.decode("utf-8"))

    def length(self):
        return len(self.get_data())

class File(DataType):
    def __init__(self, name, size, data, _type):
        DataType.__init__(self, _type, data)
        self.__name = name
        self.__size = size

    def save(self, path=None):
        if not path:
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.__name)
        with open(path, 'wb') as f:
            f.write(self.get_data())

    def get_name(self):
        return self.__name

    def get_size(self):
        return self.__size

    def get_extension(self):
        tokens = self.__name.split('.')
        return tokens[len(tokens)-1]

class SavedFile(File):
    def __init__(self, name, size):
        File.__init__(self, name, size, None, constants.SAVED_FILE)

class Object(DataType):
    def __init__(self, data):
        DataType.__init__(self,  constants.OBJECT, data)

class List(DataType):
    def __init__(self, data):
        DataType.__init__(self,  constants.LIST, data)

    def length(self):
        return len(self.get_data())
