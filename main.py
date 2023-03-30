import sys,threading,socket
import argon2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


privKey = Ed25519PrivateKey.generate()
pubKey = privKey.public_key()
partKey = None
signat = None
user = None


def send_message(c):
  while True:
    message = (user + ': ' + (input(user + ':')))
    smsg = private_key.sign(message.encode())
    c.send(message.encode())
    c.send(smsg)
#    print(user + ': ' + message)
def recv_message(c):
  while True:
    plain = c.recv(1024).decode()
    signd = c.recv(1024).decode()
    try:
      partKey.verify(smsg, message)
    except:
      sys.exit('Message Verification Failed')
    else:
      print(plain)
    

user = input('Enter username: ')
choice = input('Host or Connect?\n')

if choice.lower() == 'host':
  server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
#  hostname = input('Enter Hostname or IP')
  server.bind(('0.0.0.0',7443))
  server.listen()

  client,_ = server.accept()
  client.send(pubKey)
  partKey = client.recv(1024)
elif choice.lower() == 'client':
  serveraddr = input('Server IP: ')
  client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  client.connect((serveraddr,7443))
  client.send(pubKey)
  partKey = client.recv(1024)
else:
  sys.exit('Invalid Option')

shared_key = private_key.exchange(ec.ECDH(), partKey)
derived_key = HKDF(
    algorithm=hashes.SHA512(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(shared_key)

threading.Thread(target=send_message,args=(client,))
threading.Thread(target=recv_message,args=(client,))
