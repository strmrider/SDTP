[![Python 3.8](https://img.shields.io/badge/python-3.8-green.svg)](https://www.python.org/downloads/release/python-380/)
[![Linux](https://img.shields.io/badge/Ubuntu-20.04-blue.svg)](https://www.python.org/downloads/release/python-360/)
[![Windows](https://img.shields.io/badge/Windows-10-blue.svg)](https://www.python.org/downloads/release/python-360/)
# Secured-Internet-Protocol
Secured data (bytes, text, files and objects) transfer internet protocol using a thrid party certifiacte authntication server, hybrid encryptions and digital signatures.

The protocol is [presentation layer](https://en.wikipedia.org/wiki/Presentation_layer) related and serves as an infrastructure for TCP-based application layer protocols, providing data encryption/decryption and serializations.
## Features
* Hybrid encryption, using both RSA and AES algorithms.
* Digital singatures (using SHA256).
* Multipile types of data such as raw bytes, plain text, files and serialized python objects.
* Third party managble authntication server.
* Non-blocking socket connections.
* Simple API.

## Dependencies
* Python 3.8.5 built-in packages
* [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/index.html)
* [tabulate](https://pypi.org/project/tabulate/)

## How to use
### Certificate authority
First establish the Certificate authority (CA) server. The Server's public key should be known by all clients in advance. The use of this server is optional in case no third party confirmation is desiered.
```Python
from .ca import caserver

# connection data
IP = '238.25.163.254'
PORT = 45123

# generates new public and private keys
key = caserver.generate_key(1024)
# in case key exists
key = caserver.read_key("private.pem")
server = caserver.CAServer(IP, PORT, key)
server.start()
# call the stop method to pause the server
server.stop()
```
#### Database
Clients must be registered to the CA server in order to receive a certificate for their public key.
```Python
# get database
db = server.get_database()
# load an existed database file
db.load("cadatabase.db")
# add new user. parametrs are username and password
new_user = caserver.create_client("user1", "user1password")
db.add(new_user)
# save database. parameter should be a file path in case that no database was loaded
db.save_to_file()
```

### Session handler
The handler manages all the functionality of the session. The handler must have the connection(server or client socket) of the current stream.

#### Receive and send data
```Python
# send binary data
session.send_bytes(binary_data)
# send text
session.send_text(text)
# send a file
session.send_file(filename, file_content)
# send an object (dict)
session.send_object(object)
# send list
session.send_list(list)
```
Receive data with receive() method. See 'Data types' section to learn how to use received data
```Python
data = session.receive()

# check data type
from . import constants

type = data.get_type()
if type == constants.BYTES:
    print ("Raw Bytes")
elif type == constants.TEXT:
    print ("Plain text")
```
#### Data types
As already mentioned, the protocol supports the transfer of general binary data, text, files, serialized python objects (also dictionary), lists and tuples (the serialization uses Python built in ['pickle'](https://docs.python.org/3/library/pickle.html) module)
```Python
from . import constants

type = data.get_type()
if type == constants.BYTES or type == constants.OBJECT or type == constants.LIST:
    data.get_data()
elif type == constants.TEXT:
    data.get_text()
elif type == constants.FILE:
    filename = data.get_name()
    extension = data.get_extension()
    size = data.get_size()
    # save file. if no path is provided, the file will be saved in local dir with the original filename
    data.save()
```
### Client and server
The library provides base client and server classes, which are suffice for most applications. The classes could be overriden and expanded for more functions and properties.
* CA server is optional and the client/server should include the .pem file of its public key (should be provided by the CA server itself in advance).
* Use threads in order to use both receive and send functions simultaneously.
#### Server
```Python
from src.service.baseserver import BaseServer

# server's data
IP = '64.26.65.211'
PORT = 55655

# create a session handler that handles the sessions with income clients
def handle_session(session):
    data = session.receive()
    session.send_text(data.get_text())

# generates server's own keys
key = session_handler.generate_rsa_keys(1024)
server = BaseServer(key)
# set the handler
server.handle_session = session_handler
server.start(IP, PORT)
```
With certificate authentication:
```Python
from src.service.baseserver import BaseServer

# ca data
ca_ip = '238.25.163.254'
ca_port = 45123
ca_key = 'ca_pkey.pem'
# get signed certificate from ca server
certificate = session_handler.request_certificate(your_username, your_password, key.publickey(), ca_key, (ca_ip, ca_port))
# checks if certificate was granted
if certificate:
    print ("certificate granted!")
    # set certficate mode and the certificate itself
    server.set_cert_mode(certificate)
    # true for non-blocking socket
    server.start(IP, PORT, True)
else:
    print("certificate denied!")
```

#### Client
```Python
# server's data
IP = '64.26.65.211'
PORT = 55655

# create base client
client = baseclient.BaseClient()
# connect to server
client.connect(IP, PORT)
# get session object and manage the session
session = client.get_session()
session.send_text("hello")
```
With certificate authentication:
```Python
# read ca key
ca_key = session_handler.read_key(ca_key_file)
# set client to use certificate authority
client.set_cert_mode(ca_key)
client.connect(IP, PORT)
```
