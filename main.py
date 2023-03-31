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
    message = (user + ': ' + (input(user + ':'))).encode()
    smsg = (private_key.sign(message)).encode()
    c.send(message)
    c.send(smsg)
#    print(user + ': ' + message)
def recv_message(c):
  while True:
    plain = c.recv(1024).decode()
    signd = c.recv(1024).decode()
    try:
      partKey.verify(smsg, plain)
    except:
      sys.exit('Message Verification Failed')
    else:
      print(plain)
    

user = input('Enter username: ')
choice = input('Host or Connect?\n')

if choice.lower() == 'host':
  server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
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


threading.Thread(target=send_message,args=(client,))
threading.Thread(target=recv_message,args=(client,))
