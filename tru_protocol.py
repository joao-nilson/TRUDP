import socket
import time
import threading
from packet import TRUPacket, PacketType
from typing import Optional, List
from congestion import CongestionControl

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

        self.send_window = []
        self.receive_buffer = []
        self.window_size = 4
        self.base_seq = 0
        self.next_seq = 0

        self.congestion = CongestionControl()

        self.receiver_thread = None
        self.running = False

    def start(self):
        self.running = True
        self.receiver_thread = threading.Thread(target=self._receiver_loop)
        self.receiver_thread.start()

    def _receiver_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(2048)
                packet = TRUPacket.deserialize(data)
                self._process_packet(packet, addr)
            except:
                continue

    def _process_packet(self, packet: TRUPacket, addr: Tuple[str, int]):
        if packet.packet_type == PacketType.ACK:
            self._update_send_window(packet.ack_num)

        elif packet.packet_type == PacketType.DATA:
            self.receive_buffer.append(packet)

            ack_packet = TRUPacket(ack_num=packet.seq_num + 1, packet_type=PacketType.ACK)
            self._send_raw(ack_packet.serialize(), addr)

    def send(self, data: bytes) -> bool:
        if not self.connected or not self.peer_addr:
            return False

        packet_size = 1400
        packets = []

        for i in range(0, len(data), packet_size):
            chunk = data[i:i+packet_size]
            packet = TRUPacket(seq_num=self.next_seq, packet_type=PacketType.DATA, data=chunk, timestamp=time.time())
            self.next_seq += 1
            packets.append(packet)
        
        for packet in packets:
            while len(self.send_window) >= self.window_size:
                time.sleep(0.1)
            self.send_window.append(packet)
            self._send_raw(packet.serialize(), self.peer_addr)

        return True

    def _update_send_window(self, ack_num: int):
        self.send_window = [p for p in self.send_window if p.seq_num >= ack_num

    def receive(self, timeout: float = 1.0) -> Optional[bytes]:
        start_time = time.time()

        while time.time() - start_time < timeout:
            if self.receive_buffer
                for i, packet in enumerate(self.receive_buffer):
                    if packet.seq_num  == self.base_seq:
                        self.receive_buffer.pop(i)
                        self.base_seq += 1
                        return packet_data
            time.sleep(0.01)

        return None

    def close(self):
        if self.connected and self.peer_addr:
            fin_packet = TRUPacket(
                seq_num=self.next_seq,
                packet_type=PacketType.FIN,
                timestamp=time.time()
            )
            self._send_raw(fin_packet.serialize(), self.peer_addr)
            self.next_seq += 1

            try:
                self.sock.settimeout(2.0)
                data, _ = self.sock.recvfrom(1024)
                packet = TRUPacket.deserialize(data)

                if packet.packet_type == PacketType.FIN_ACK:
                    print("COnexão fechou de forma correta")
            except socket.timeout:
                print("Conexão fechada por timeout")
        
        self.running = False
        if self.receiver_thread:
            self.receiver_thread.join(timeout=1.0)
        self.sock.close()
        self.connected = False

    def _send_raw(self, data: bytes, addr: Tuple[str, int]):
        try:
            self.sock.sendto(data, addr)
        except Exception as e:
            print(f"Erro ao enviar dados: {e}")

    def connect(self, host: str, port: int) -> bool:
        self.peer_addr = (host, port)

        #SYN
        syn_packet = TRUPacket(seq_num=self.next_seq, packet_type=PacketType.SYN, timestamp=time.time())
        self.next_seq += 1
        self.__send_packet(syn_packet, self.peer_addr)

        #espera SYN-ACK
        start_time = time.time()
        while time.time() - start_time < 5.0:
            try:
                self.sock.settimeout(1.0)
                data, addr = self.sock.recvfrom(1024)
                packet = TRUPacket.deserialize(data)

                if (packet.packet_type == PacketType.SYN_ACK and
                    packet.ack_num == syn_packet.seq_num + 1):

                    ack_packet = TRUPacket(
                        seq_num=packet.ack_num,
                        ack_num=packet.seq_num + 1,
                        packet_type=PacketType.ACK,
                        timestamp=time.time()
                    )
                    self._send_packet(ack_packet, self.peer_addr)

                    self.connected = True
                    self.base_seq = packet.ack_num
                    return True

            except socket.timeout:
                continue

        return True

    def accept_connection(self) -> bool:
        while True:
            data, addr = self.sock.recvfrom(1024)
            packet = TRUPacket.deserialize(data)
            
            if packet.packet_type == PacketType.SYN:
                syn_ack_packet = TRUPacket(
                    seq_num=self.next_seq,
                    ack_num=packet.seq_num + 1,
                    packet_type=PacketType.SYN_ACK,
                    timestamp=time.time()
                )
                self.next_seq += 1
                self._send_packet(syn_ack_packet, addr)
                
                self.sock.settimeout(5.0)
                try:
                    data, _ = self.sock.recvfrom(1024)
                    ack_packet = TRUPacket.deserialize(data)
                    
                    if ack_packet.packet_type == PacketType.ACK:
                        self.peer_addr = addr
                        self.connected = True
                        self.base_seq = ack_packet.seq_num
                        return True
                        
                except socket.timeout:
                    continue
