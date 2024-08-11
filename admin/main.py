import hashlib
import socket
import os
import logging
import threading

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization

SERVER_PORT = 9999
SERVER_HOST = '127.0.0.1'
SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 4096
host = "127.0.0.1"
port = 5001
PATH_TO_PUBLICKEY = 'public_key.pem'
PATH_TO_PRIVATEKEY = 'private_key.pem'

logging.basicConfig(level=logging.DEBUG)
groups = {"test": [('127.0.0.1', 5001)]}
sendinglist = {}


def sign_hash(hash_value, private_key_path):
    # Load the private key from a file
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    # Sign the hash
    signature = private_key.sign(
        hash_value,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return signature

def verify_signature(signature, hash_value, public_key_path):
    # Load the public key from a file
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    
    try:
        public_key.verify(
            signature,
            hash_value,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False


def connect_and_send(filename, addr, to_send_list=[]):
    filesize = os.path.getsize(filename)
    if addr == None:
        addr = to_send_list[0]
        to_send_list = to_send_list[1:]
    while True:
        try:
            s = socket.socket()
            print(f"[+] Connecting to {addr[0]}:{addr[1]}")
            s.connect(addr)
            print("[+] Connected.")
            s.sendall(f"{filename}{SEPARATOR}{filesize}".encode())
            ack = s.recv(BUFFER_SIZE).decode()
            if ack == 'STARTTOSEND':
                for i in to_send_list:

                    s.sendall(f"{i[0]} {i[1]}".encode())
                    data = s.recv(BUFFER_SIZE).decode()
                    if data != 'NEXT': 
                        logging.warning(f"Expected NEXT but got {data}")
                s.sendall('END'.encode())
            else:
                logging.debug(f"Did not recv STARTTOSEND")
            ack = s.recv(BUFFER_SIZE).decode()
            if ack == 'STARTDATA':
                pass
            else:
                # retransmittion of data
                pass
            hash_func = hashlib.new('sha256')
            with open(filename, "rb") as f:
                while True:
                    bytes_read = f.read(BUFFER_SIZE)
                    if not bytes_read:
                        s.sendall("END".encode())
                        break
                    hash_func.update(bytes_read)
                    s.sendall(bytes_read)
                    
                    print(f"{len(bytes_read)}/{filesize}")
            ack = s.recv(BUFFER_SIZE).decode()
            if ack == 'SENDHASH':
                signature = sign_hash(hash_func.digest(), PATH_TO_PRIVATEKEY)
                s.sendall(signature)
                logging.debug(signature)
            else: 
                # Handle
                pass
            ack = s.recv(BUFFER_SIZE).decode()
            if ack == 'END':
                pass
            # close the socket
            logging.info(f"Closing connection {addr}")
            s.close()
            break
        except (socket.error, ConnectionRefusedError) as e:
            logging.error(f'Could not connect {addr}')
            # TODO: Send info to admin
            if not to_send_list: break
            addr = to_send_list[0]
            to_send_list = to_send_list[1:]


def get_ack(group):
    if group not in groups: 
        logging.error(f"No group with name {group}")
        return
    sentfile = {
        f"{key[0]} {key[1]}": False for key in groups[group]
    }
    cnt = len(sentfile)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((SERVER_HOST, SERVER_PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            data = conn.recv(BUFFER_SIZE).decode()
            host, status = data.split(SEPARATOR)
            if host in sentfile:
                if not sentfile[host]:
                    logging.debug(f"File sent sataus for {host} is {status}")
                    sentfile[host] = True
                    cnt -= 1
                    if cnt >= 0:
                        break
                else:
                    logging.debug(f"{host} has sent dublicate ack {status=}")
            else:
                logging.warning(f"File sent msg came from {host} who is not in the current group")
                
            # threading.Thread(target=handle_client, args=(conn, addr)).start()


if __name__ == "__main__":
    while True:
        cmd = input(">>>")
        cmd.strip()
        cmdl = cmd.split()
        if cmdl[0].lower() == 'send':
            if len(cmdl) == 3:
                filename = cmdl[1]
                group = cmdl[2]
                if group not in groups: 
                    logging.error(f"No group with name {group}")
                    continue
                ack = threading.Thread(target=get_ack, args=(group,))
                ack.start()
                connect_and_send(filename, None, groups[group])
                ack.join()
            else:
                print("Invalid syntax")
                print("Usage: send <file_name> <group_name>")
        elif cmdl[0].lower() == 'addgroup':
            group = cmdl[1]
            l = cmdl[2]
            if len(cmdl) == 3:
                if cmdl[1] in groups:
                    print("Group already exist")
                    continue
                try:
                    groups[group] = eval(l)
                except SyntaxError as e:
                    print("Invalid host names list syntax")
            else:
                print("Invalid syntax")
                print("Usage: addgroup <group_name> [(<hostname>,<port>), ...]")
                print("NOTE: Please dont give spaces in the list of users")
                print("You can add user later as well")
        elif cmdl[0].lower() == 'addusers':
            if len(cmdl) == 3:
                l = cmdl[1]
                group = cmdl[2]
                if group not in groups:
                    print("Group does not exist")
                    continue
                try:
                    groups[group].extend(eval(l))
                except SyntaxError as e:
                    print("Invalid host names list syntax")
                
            else:
                print("Invalid syntax")
                print("Usage: addusers [(<hostname>, <port>), ...] <group_name>")
                print("NOTE: Please dont give spaces in the list of users")
        elif cmdl[0].lower() == 'group':
            if len(cmdl) == 2:
                group = cmdl[1]
                print(f"'{group}'")
                if group not in groups:
                    print("Group does not exist")
                    continue
                print(groups[group])
            else:
                print("Invalid syntax")
                print("Usage: group <group_name>")
        elif cmdl[0].lower() == 'groups':
            if len(cmdl) == 1:
                print('\n'.join(list(groups.keys())))
            else:
                print("Invalid syntax")
                print("Usage: groups")
        else:
            print("Usage: send <file_name> <group_name>")
            print("Usage: addgroup <group_name> [(<hostname>, <port>), ...]")
            print("Usage: addusers [(<hostname>, <port>), ...] <group_name>")
            print("Usage: group <group_name>")
            print("Usage: groups")
            
        
        