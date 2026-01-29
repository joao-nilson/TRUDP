import socket
import time
import threading
from packet import TRUPacket, PacketType
from typing import Optional, Tuple, Callable, List
from congestion import CongestionControl
import random

MSS = 1400

class TRUProtocol:

    def __init__(self, host='0.0.0.0', port=5000, is_server=False, loss_callback=None):
        self.host = host
        self.port = port
        self.is_server = is_server
        self.loss_callback = loss_callback

        #socket udp
        self.sock = socket.socket(socket.AF_INET, sock.SOCK_DGRAM)
        if is_server:
            self.sock.bind((host, port))

        self.sock.settimeout(1.0)

        self.ack_num = self.base_seq
        self.send_window = []
        self.received_segments = set()
        
        #status connection
        self.connected = False
        self.peer_addr = None
        
        #seq numbers
        self.base_seq = random.randint(0, 2**31 -1)
        self.next_seq = self.base_seq
        self.ack_sum = 0
        
        #buffers
        self.send_buffer = {} # seq -> packet, sent_time, retries
        self.receive_buffer = {} # seq -> data
        self.receive_segments = set()
        
        #window control
        self.window_size = 4
        self.congestion = CongestionControl()
        
        #thread control
        self.receive_thread = None
        self.running = False
        
        #queue
        self.app_queue = []

    def start(self):
        self.running = True
        self.receiver_thread = threading.Thread(target=self._receiver_loop)
        self.receiver_thread.daemon = True
        self.receiver_thread.start()

    def _receiver_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(2048)
                packet = TRUPacket.deserialize(data)
                self._process_packet(packet, addr)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Receiver erro: {e}")
                continue

    def _process_packet(self, packet: TRUPacket, addr: Tuple[str, int]):
        if not self.peer_addr:
            self.peer_addr = addr

        if self.loss_callback and self.loss_callback(packet.seq_num):
            print(f"Packet {packet.seq_num} dropped")
            return

        if packet.packet_type == PacketType.ACK:
            self._handle_ack(packet)
        elif packet.packet_type == PacketType.DATA:
            self._handle_data(packet, addr)
        elif packet.packet_type == PacketType.SYN:
            self._handle_syn(packet, addr)
        elif packet.packet_type == PacketType.SYN_ACK:
            self._handle_syn_ack(packet)
        elif packet.packet_type == PacketType.FIN:
            self._handle_fin(packet)
        elif packet.packet_type == PacketType.FIN_ACK:
            self._handle_fin_ack()

    def _handle_syn(self, packet: TRUPacket, addr: Tuple[str, int]):
        if self.connected:
            return
            
        syn_ack_packet = TRUPacket(
            seq_num=self.next_seq,
            ack_num=packet.seq_num + 1,
            packet_type=PacketType.SYN_ACK,
            timestamp=time.time()
        )
        self.next_seq += 1
        self._send_raw(syn_ack_packet.serialize(), addr)
        
        self.peer_addr = addr

    def _handle_syn_ack(self, packet: TRUPacket):
        if self.connected:
            return
            
        if packet.ack_num == self.base_seq + 1:
            ack_packet = TRUPacket(
                seq_num=packet.ack_num,
                ack_num=packet.seq_num + 1,
                packet_type=PacketType.ACK,
                timestamp=time.time()
            )
            self._send_raw(ack_packet.serialize(), self.peer_addr)
            
            self.connected = True
            self.base_seq = packet.ack_num
            self.next_seq = packet.ack_num
            print(f"Connection established with {self.peer_addr}")

    def _handle_ack(self, packet: TRUPacket):
        ack_num = packet.ack_num

        for seq in list(self.send_buffer.keys()):
            if seq < ack_num:
                del self.send_buffer[seq]

        self.congestion.on_ack_received()
        self.window_size = self.congestion.get_window_size()

    def _handle_data(self, packet: TRUPacket, addr: Tuple[str, int]):
        if packet.seq_num in self.received_segments:
            return

        self.receive_buffer[packet.seq_num] = packet.data
        self.received_segments.add(packet.seq_num)

        ack_packet = TRUPacket(
            packet_num=packet.seq_num + len(packet.data),
            packet_type=PacketType.ACK,
            timestamp=time.time()
        )
        self._send_raw(ack_packet.serialize(), addr)

        self._deliver_data()

    def _deliver_data(self):
        sorted_seqs = sorted(self.receive_buffer.keys())

        for seq in sorted_seqs:
            if seq == self.ack_num:
                data = self.receive_buffer.pop(seq)
                self.app_queue.append(data)
                self.ack_num += len(data)

    def _handle_fin(self, packet: TRUPacket):
        if not self.connected:
            return
            
        fin_ack_packet = TRUPacket(
            seq_num=self.next_seq,
            ack_num=packet.seq_num + 1,
            packet_type=PacketType.FIN_ACK,
            timestamp=time.time()
        )
        self.next_seq += 1
        self._send_raw(fin_ack_packet.serialize(), self.peer_addr)
        
        self.connected = False
        print(f"Connection closed by peer {self.peer_addr}")

    def _handle_fin_ack(self):
        if self.connected:
            self.connected = False
            print(f"Connection closed with {self.peer_addr}")

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
        self.send_window = [p for p in self.send_window if p.seq_num >= ack_num]

    def receive(self, timeout: float = 1.0) -> Optional[bytes]:
        start_time = time.time()

        while time.time() - start_time < timeout:
            if self.app_queue:  # Verificar a fila de aplicação
                return self.app_queue.pop(0)
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
        syn_packet = TRUPacket(
            seq_num=self.next_seq,
            packet_type=PacketType.SYN, 
            timestamp=time.time()
        )
        self.next_seq += 1
        self.__send_raw(syn_packet.serialize(), self.peer_addr)

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
                    self._send_raw(ack_packet.serialize(), self.peer_addr)

                    self.connected = True
                    self.next_seq = packet.ack_num
                    return True

            except socket.timeout:
                continue

        return True

    def accept(self) -> bool:
        if not self.is_server:
            return False
        
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)
                packet = TRUPacket.deserialize(data)
                
                if packet.packet_type == PacketType.SYN:
                    self.peer_addr = addr

                    syn_ack_packet = TRUPacket(
                        seq_num=self.next_seq,
                        ack_num=packet.seq_num + 1,
                        packet_type=PacketType.SYN_ACK,
                        timestamp=time.time()
                    )
                    self.next_seq += 1
                    self._send_packet(syn_ack_packet.serialize(), addr)
                    
                    self.sock.settimeout(5.0)
                    try:
                        data, _ = self.sock.recvfrom(1024)
                        ack_packet = TRUPacket.deserialize(data)
                        
                        if ack_packet.packet_type == PacketType.ACK:
                            self.connected = True
                            self.base_seq = ack_packet.seq_num
                            return True
                            
                    except socket.timeout:
                        continue
            except Exception as e:
                print(f"Accept error: {e}")
                return False
    
    def send_data(self, data: bytes, progress_cb=None) -> bool:
        if not self.connected or not self.peer_addr:
            return False
            
        segments = []
        for i in range(0, len(data), MSS):
            segment = data[i:i+MSS]
            segments.append(segment)
            
        total_segments = len(segments)
        
        for i, segment in enumerate(segments):
            while len(self.send_buffer) >= self.window_size:
                time.sleep(0.01)
                
            packet = TRUPacket(
                seq_num=self.next_seq,
                packet_type=PacketType.DATA,
                data=segment,
                timestamp=time.time()
            )
            self.next_seq += len(segment)
            
            self.send_buffer[packet.seq_num] = (packet, time.time(), 0)
            self._send_raw(packet.serialize(), self.peer_addr)
            
            self.congestion.on_packet_sent()
            
            if progress_cb:
                progress_cb(i+1, total_segments)
                
        start_time = time.time()
        while self.send_buffer and time.time() - start_time < 30.0:
            time.sleep(0.1)
            
        return len(self.send_buffer) == 0

    def recv_data(self, expected_segments: int, progress_cb=None) -> bytes:
        data = b''
        received_segments = 0
        start_time = time.time()
        
        while received_segments < expected_segments and time.time() - start_time < 30.0:
            if self.app_queue:
                segment = self.app_queue.pop(0)
                data += segment
                received_segments += 1
                
                if progress_cb:
                    progress_cb(received_segments, expected_segments)
            else:
                time.sleep(0.01)
                
        return data