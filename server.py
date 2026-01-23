import socket

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 5000))

    print("Server listening on port 5000")

    while True:
        data, addr = sock.recvfrom(1024)
        print(f"Received from {addr}: {data.decode()}")

        response = b"Message received"
        sock.sendto(response, addr)

if __name__ == '__main__':
    main()
