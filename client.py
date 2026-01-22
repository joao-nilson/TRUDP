import socket
import sys

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = ('localhost', 5000)

    #envia
    message = b"Hello TRUDP!"
    sock.sendto(message, server_addr)
    
    #receve
    data, addr = sock.recvfrom(1024)
    print(f"Received: {data.decode()}")

    sock.close

if __name__ == '__main__':
    main()
