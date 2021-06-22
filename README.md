[![Python 3.8](https://img.shields.io/badge/python-3.8-green.svg)](https://www.python.org/downloads/release/python-380/)
[![Linux](https://img.shields.io/badge/Ubuntu-20.04-blue.svg)](https://www.python.org/downloads/release/python-360/)
[![Windows](https://img.shields.io/badge/Windows-10-blue.svg)](https://www.python.org/downloads/release/python-360/)
# Secured-Data-Transfer-Protocol
Secured data (bytes, text, files and objects) transfer internet protocol using a thrid party certifiacte authntication server, hybrid encryptions and digital signatures.

The protocol is [presentation layer](https://en.wikipedia.org/wiki/Presentation_layer) related and serves as an infrastructure for TCP-based application layer protocols, providing data encryption/decryption and serializations.
## Features
* Hybrid encryption, using both RSA and AES algorithms.
* Digital singatures (using SHA256).
* Multipile types of data such as raw bytes, plain text, files and serialized python objects.
* Data compression.
* Third party managble authntication server.
* Non-blocking socket connections.
* Services kit including base client/server, proxy server and VPN functionalities.
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

### Session
##### Socket wrapper
Wrap your socket object to use improved receive and send funtions
```Python
from .sock import Wrapper

wrapped_socket = Wrapper(YOUR SOCKET OBJECT)
```
#### Hanshake
The handshake performs private and session keys exchange and certificate verfication.

Server:
```Python
from . import handshake
private_key = [SERVER'S PRIVATE KEY]
network = [WRAPPED SOCKET]
# without certificate
session_key = handshake.server_handshake(private_key, network)
# with a certificate
certificate = [CERTIFICATE FROM CA SERVER]
session_key = handshake.server_handshake_cert(private_key, network, certificate)
```
Client
```Python
import os
# encryption key size (in bytes)
KEY_SIZE = 16
session_key = os.urandom(KEY_SIZE)
network = [WRAPPED SOCKET]
# without certificate
handshake.client_handshake(newtwork, session_key)
# with a certificate
ca_public_key = [ca server public key]
handshake.client_handshake_cert(session_key, network, ca_public_key)
```
#### Session handler
The handler manages all the functionality of the session. The handler must have the connection(server or client socket) of the current stream.
After the handshake procedure, create the session handler and use it to send and receive data:
```Python
from .session import Session

session = Session(network, session_key)
```
#### API
#### ``Session(network, session_key, compress_mode=False)``
Creates a session. Receives wrapped socket and generated session key. Set *compress_mode* as True to compress the trasnferred data. Note: Data compression isn't alaways efficient. Use it to transfer large size data.
    
* **``receive()``**

    Receives data from the session. Returns DataType object which stores the data type and the received data.

* **``send_bytes(data)``**

    Sends raw bytes.

* **``send_text(text)``**

    Sends text.

* **``send_raw_file(filename, bin_file)``*
    
    Sends file's content in one peice. Receives filename and file's content.

* **``send_file(path)``**

    Sends a file in chunks instead of reading all of it into memory. Each chunk's size is defined by *max_memory* function.

* **``send_object(obj)``**

    Sends an Object (python Dictionary).

* **``send_list(list_items)``**

    Sends a lists and tuples

* **``set_autosave(status)``**

    Set True to save files automatically When receiving files in chunks instead of collecting them in memory.
    
* **``max_memory(size)``**
    
    Sets meximum bytes in memory when sending or receiving files.
    
* **``set_files_dir(directory)``**
    
    Sets the target directory for automatic file saving.

##### Receive and send data
See 'Data types' section to learn how to use received data.
```Python
# check data type
from . import constants

# recieve data
type = data.get_type()
if type == constants.BYTES:
    print ("Raw Bytes")
elif type == constants.TEXT:
    print ("Plain text")

# send data

# send binary data
session.send_bytes(binary_data)
# send text
session.send_text(text)
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
Types:
* Bytes - raw bytes
* Text - plain text
* File - file in bytes (name, extension and size are accessible)
    * Saved File - reference to a saved file (located in save target directory) without the data in bytes
* Object - dict
* List - list or tuple

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
from .service.baseserver import BaseServer
from . import handshake

# ca data
ca_ip = '238.25.163.254'
ca_port = 45123
ca_key = 'ca_pkey.pem'
# get signed certificate from ca server
certificate = handshake.request_certificate(your_username, your_password, key.publickey(), ca_key, (ca_ip, ca_port))
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
ca_key = handshake.read_key(ca_key_file)
# set client to use certificate authority
client.set_cert_mode(ca_key)
client.connect(IP, PORT)
```

### Proxy
The proxy server creates a tunnel between two nodes which use the protocol.

Client
```python
from .services.proxy import ProxyClient

# sample addresses and ports
proxy_ip = '65.124.78.02'
proxy_port = 25411

target_ip = '65.140.89.14'
target_port = 41512

proxy_client = ProxyClient()
proxy_client.connect((proxy_ip, proxy_port), (target_ip, target_port))
session = proxy_client.get_session()
# use session...
```
Server
```Python
from .services.proxy import ProxyServer

IP = '125.208.78.02'
PORT = 25411

server = ProxyServer()
server.run(IP, PORT)
```

### VPN
While not exactly a VPN, the service can be used as a mediator for local machine sockets and an external server without using the protocol directly. By that, it can provide the VPN functionalities of anonymity and security (encrypted traffic). 

Very useful for network communication between two nodes that don't use the protocol, or when you want to use any other programing langauage other than python.

First run the VPN server
```Python
from .service.vpn.vpnsrv import VPNServer

vpn_server = VPNServer()
vpn_server.start(IP, PORT)
```
Run the client on local machine
```Python
from .service.vpn.vpnclient import VPNClient

# set client port
client = VPNClient(24156)
client.run(VPN_IP, VPN_PORT)
```
Use the service with your sockets as usual
```Python
import socket
from .service.vpn.vpnclient import send_target_info

# set target ip address and port
taregt_ip = '125.208.78.02'
target_port = 25411

s = socket.socket(socket.AF_INET, sokcet.SOCK_STREAM)
# connect to the VPN client on local machine
s.connect(('127.0.0.1', VPN_PORT))
# send target server ip address and port to the VPN client
send_target_info(taregt_ip, target_port, s)

# use the socket as usual and the VPN client will handle the traffic
```
