import socket
import time
import threading
from packet import TRUPacket, PacketType

class TRUProtocol:
    def __init__(self, host='0.0.0.0', port=5000, is_server=False):
        self.host = host
        self.port = port
        self.is_server = is_server

        #socket udp
        self.socket = socket.socket(socket.AF_INET, sock.SOCK_DGRAM)
        if is_server:
            self.sock.bind((host, port))

        self.connected = False
        self.peer_addr = None
        self.seq_num = 0
        self.expected_seq = 0

    def connected(self, host, port):
        self.peer_addr = (host, port)

        #envia
        syn_packet = TRUPacket(seq_num=self.seq_num, packet_type=PacketType.SYN)
        self.seq_num += 1
        self._send_raw(syn_packet.serialize())
        
        #recebe ack
        data, addr = self.sock.recvfrom(1024)
        packet = TRUPacket.deserialize(data)

        if packet.packet_type == PacketType.SYN_ACK:
            self.connected = True
            return True
        return False

    def send(self, data: bytes):
        if not self.connected:
            return False

        packet = TRUPacket(seq_num=self.seq_num, packet_type=PacketType.DATA, data=data)
        self.seq_num += 1
        self._send_raw(packet.serialize())
        return True

    def receive(self):
        data, addr = self.sock.recvfrom(1024)
        packet = TRUPacket.deserialize(data)

        if packet.packet_type == PacketType.DATA:
            ack_packet = TRUPacket(ack_num=self.seq_num, packet_type=PacketType.ACK)
            self._send_raw(ack_packet.serialize())
        
        return packet.data

    def _send_raw(self, data: bytes):
        self.sock.sendto(data, self.peer_addr)

    def close(self):
        if self.connected:
            fin_packet = TRUPacket(packet_type=PacketType.FIN)
            self._send_raw(fin_packet.serialize())
        self.sock.close()
