# Secured-Internet-Protocol
Secured data, files and text transfer internet protocol using a thrid party certifiacte authntication server, encryptions and digital signatures.

## Model

### Data types
The protocol supports the transfer of general binary data, text and files
```Python
import data_types

bytes = data_types.Bytes(your_data)
text = data_types.Text(your_text)
bytes = data_types.File(your_filename, your_file_content)

# get data
bytes.get_data()
text.get_text()
file.get_name()
file.get_size()
file.get_data()
```
## How to use
### Certificate authority
Located in the 'ca_server' folder
```Python
ca = CertificateAuthority()
ca.start()
```
#### Database
Clients must be registered in the CA server in order to receive a certificate for their public key
```Python
import models.lient

client = models.client.Client(123456, "User1")
ca.database.add(client)
ca.database.get(client.id)
ca.database.remove(client.id)
```
### User and server details
```Python
import models.details as details

user = details.UserDetails()
user.id = 1551
user.name = "User"
user.decryptor = rsa.Decryptor()

# certificate authority server. Insert the server's ip, port and public key
ca_details = details.CAServerDetails(127.0.0.1, 32410, (287, 7))
```
### Certificate
```Python
import handler

certificate = handler.get_certificate_from_ca_server(self.details.id, self.details.name, self.ca_server_details, self.details.decryptor)
````
### Session handler
The handler manages all the functionality of the session. The handler must have the connection(server or client socket) of the current stream.
```Python
import network as net
import constants

session = handler.Handler(net.Network(HERE_IS_THE_SOCKET), user.id, user.name, ca_details, user.decryptor)
```
#### Handshake
```Python
# server
session.handshake(constants.SERVER_HANDSHAKE)
# client
self.session.handshake(constants.CLIENT_HANDSHAKE)
````

#### Receive and send data
```Python
data = session.receive()
```
```Python
# send binary data
session.send_bytes(here_is_binary_data)
# send text
session.send_text(here_is_some_text)
# send a file
session.send_file(filename, file_content)
```
### Sample application
Here is a simple application example that uses the protocol.
#### Server
See .py file
Simple server the accepts clients and adds them to a clients list.
```Python
import server
import rsa.rsa as rsa

user = details.UserDetails()
user.id = 1551
user.name = "User1"
user.decryptor = rsa.Decryptor()

ca_details = details.CAServerDetails(127.0.0.1, 32410, (287, 7))

server = Server(user, ca_details)
server.start(socket.gethostname(), 32411)
```
Access a client from the list and hanle the session
```Python
client = server.get_client(your_client_name)
client.receive()
client.send()
```
#### Client
```Python
import client

client = Client(user_details, ca_details)
client.connect(your_serve_ip, 32411)
client.get_session().send_text("hello")
```
Use threads in order to use both receive and send functions simultaneously
