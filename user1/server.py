import socket
import os
import threading
import logging

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 1234
BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"
CHILDSIZE = 2

logging.basicConfig(level=logging.DEBUG)

def connect_and_send(filename, addr, to_send_list=[]):
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
            
            with open(filename, "rb") as f:
                while True:
                    bytes_read = f.read(BUFFER_SIZE)
                    if not bytes_read:
                        break
                    s.sendall(bytes_read)
                    
                    print(f"{len(bytes_read)}/{filesize}")

            # close the socket
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
    with open(filename, "wb") as f:
        while True:
            # read 1024 bytes from the socket (receive)
            bytes_read = client_socket.recv(BUFFER_SIZE)
            if not bytes_read:    
                # nothing is received
                # file transmitting is done
                break
            # write to the file the bytes we just received
            f.write(bytes_read)
            # update the progress bar
            print(f"{len(bytes_read)}/{filesize}")

    client_socket.close()
    print(f"[-] {address} is disconnected.")
    a = chunkify(to_send_queue, CHILDSIZE)
    logging.debug(f"Divided groups are {a}")
    for i in a:
        if i:
            threading.Thread(target=connect_and_send, args=(filename, i[0], i[1:])).start()
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