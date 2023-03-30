import threading
import sys
import argon2
import socket
import quantumrandom as  qrand
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

privKey = ec.generate_private_key(
    ec.SECP384R1()
)
pubKey = privKey.public_key()
partKey = None
shared_key = None
derived_key = None


def send_message(c):
  while True:
    message = input('')
    c.send((user + ': ' + message).encode())
    print(user + ': ' + message)
def recv_message(c):
  while True:
    plain=c.recv(1024).decode()
    print(plain)
    

user=input('Enter username: ')
choice=input('Host or Connect?\n')

if choice.lower() == 'host':
  server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  #hostname = input('Enter Hostname or IP')
  server.bind(('0.0.0.0',443))
  server.listen()

  client,_ = server.accept()
  client.send(pubKey)
  partKey = client.recv(1024)
elif choice.lower() == 'client':
  serveraddr = input('Server IP: ')
  client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  client.connect((serveraddr,443))
  client.send(pubKey)
  partKey = client.recv(1024)
else:
  sys.exit('Invalid Option')

shared_key = private_key.exchange(ec.ECDH(), partKey)
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(shared_key)

threading.Thread(target=send_message,args=(client,))
threading.Thread(target=recv_message,args=(client,))
