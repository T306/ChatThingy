import threading
import sys
import argon2
import socket
import quantumrandom as  qrand
from nacl.public import PrivateKey, Box
from nacl.encoding import URLSafeBase64Encoder
from nacl.signing import SigningKey

signing_key=SigningKey.generate()
verify_key=signing_key.verify_key
verify_key_b64=verify_key.encode(encoder=URLSafeBase64Encoder)


def send_message(c):
  while True:
    message=input('')
    c.send((user+message).encode())
    print(user+message)
def recv_message(c):
  while True:
    message=input('')
    c.send(message.encode())
    print(c.recv(1024).decode())
    

user=input('Username: ')
choice=input('Host or Connect?\n')

if choice.lower() == 'host':
  server=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  server.bind(('172.31.128.50',443))
  server.listen()

  client,_=server.accept()
elif choice.lower()=='client':
  serveraddr=input('Server IP: ')
  client=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  client.connect((serveraddr,443))
else:
  sys.exit('Invalid Option')

threading.Thread(target=send_message,args=(client,))
threading.Thread(target=recv_message,args=(client,))
