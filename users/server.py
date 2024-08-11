import hashlib
import shutil
import socket
import os
import threading
import logging
import tempfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5001
BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"
CHILDSIZE = 2
PATH_TO_PUBLICKEY = 'public_key.pem'
SUCCESS_STATUS = 'SUCCESS'
FAIL_STATUS = 'FAIL'
ADMIN_HOST = '127.0.0.1'
ADMIN_PORT = 9999

logging.basicConfig(level=logging.DEBUG)

def send_status_to_admin(status):
    try:
        s = socket.socket()
        print(f"[+] Connecting to {ADMIN_HOST}:{ADMIN_PORT}")
        s.connect((ADMIN_HOST, ADMIN_PORT))
        s.sendall(f"{SERVER_HOST} {SERVER_PORT}{SEPARATOR}{status}".encode())
        s.close()
    except (socket.error, ConnectionRefusedError) as e:
        logging.error("Couldn't connect to host")

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


def connect_and_send(filename, addr, signature, to_send_list=[]):
    filesize = os.path.getsize(filename)
    
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
                    s.sendall(i.encode())
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
                s.sendall(signature)
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


def chunkify(lst,n):
    return [lst[i::n] for i in range(n)]

def handle_client(client_socket, address):
    print(f"[+] {address} is connected.")
    received = client_socket.recv(BUFFER_SIZE).decode()
    # print(f"got {received}")
    filename, filesize = received.split(SEPARATOR)

    filename = os.path.basename(filename)
    filesize = int(filesize)
    filesize_left = filesize
    to_send_queue = []
    client_socket.sendall("STARTTOSEND".encode())

    while True:
        data = client_socket.recv(BUFFER_SIZE).decode()
        if data == 'END': break
        logging.debug(data)
        host, port = data.split()
        logging.debug(f"({host}, {port})")
        port = int(port)
        # connect_and_send(filename, (host, port))
        to_send_queue.append((host, port))
        client_socket.sendall("NEXT".encode())

    client_socket.sendall("STARTDATA".encode())
    # progress = tqdm.tqdm(range(filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor=1024)
    hash_func = hashlib.new('sha256')
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        temp_file_path = tmp_file.name
        while filesize_left > 0:
            # read 1024 bytes from the socket (receive)
            bytes_read = client_socket.recv(min(filesize_left, BUFFER_SIZE))
            if not bytes_read:    
                # nothing is received
                # file transmitting is done
                break
            # write to the file the bytes we just received
            hash_func.update(bytes_read)
            tmp_file.write(bytes_read)
            filesize_left -= len(bytes_read)
            # update the progress bar
            print(f"{bytes_read}/{filesize}")
    
    data = client_socket.recv(BUFFER_SIZE).decode()
    logging.debug(f"File transfer complete result {data}")
    if data != 'END':
        # Handle
        return
    
    client_socket.sendall('SENDHASH'.encode())
    signature = client_socket.recv(BUFFER_SIZE)

    is_valid = verify_signature(signature, hash_func.digest(), PATH_TO_PUBLICKEY)
    if is_valid:
        logging.debug("The signature is valid.")
        shutil.move(temp_file_path, filename)
        send_status_to_admin(SUCCESS_STATUS)
    else:
        logging.error(f"The signature is invalid.\n Filename: {filename}\n Sent by: {address}")
        send_status_to_admin(FAIL_STATUS)
    
    logging.debug(f"Given signature: {signature.hex()}\nOut hash: {hash_func.hexdigest()}")

    client_socket.sendall("END".encode())

    client_socket.close()
    print(f"[-] {address} is disconnected.")
    a = chunkify(to_send_queue, CHILDSIZE)
    logging.debug(f"Divided groups are {a}")
    for i in a:
        if i:
            threading.Thread(target=connect_and_send, args=(filename,i[0], signature,
             i[1:])).start()
            # connect_and_send(filename, i[0], i[1:])


# Server setup
def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((SERVER_HOST, SERVER_PORT))
        s.listen()
        print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    start_server()