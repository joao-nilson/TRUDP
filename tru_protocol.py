import socket
import time
import threading
from packet import TRUPacket, PacketType
from typing import Optional, Tuple, Callable, List
from congestion import CongestionControl
from crypto import TRUCrypto
import random
import statistics
import time

MSS = 1400

class TRUProtocol:

    def __init__(self, host='0.0.0.0', port=5000, is_server=False, loss_callback=None):
        self.host = host
        self.port = port
        self.is_server = is_server
        self.loss_callback = loss_callback
        self.crypto = TRUCrypto()
        self.encryption_enabled = False
        self.encryption_key = None
        self.timer_thread = None
        self.timeout_interval = 1.0

        # RTT
        self.rtt_samples = []  # Store RTT samples for moving average
        self.rtt_avg = 0.5     # Initial RTT estimate (seconds)
        self.rtt_dev = 0.25    # Initial RTT deviation
        self.rtt_alpha = 0.125  # Weight for moving average (RFC 6298)
        self.rtt_beta = 0.25   # Weight for deviation (RFC 6298)
        self.min_rtt = 0.1     # Minimum RTT (100ms)
        self.max_rtt = 2.0     # Maximum RTT (2 seconds)

        self.sent_times = {}

        # RTT monitoring
        self.monitoring_active = False

        self.receive_stats = {
            'received': 0,
            'duplicates': 0,
            'acks_sent': 0
        }

        self.congestion_stats = {}
       
        #seq numbers
        self.base_seq = random.randint(0, 2**31 -1)
        self.next_seq = self.base_seq
        self.ack_sum = 0

        #socket udp
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if is_server:
            self.sock.bind((host, port))

        self.sock.settimeout(1.0)

        self.ack_num = self.base_seq
        self.send_window = []
        self.received_segments = set()
        
        #status connection
        self.connected = False
        self.peer_addr = None
        
        
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
        self.timer_thread = threading.Thread(target=self._timer_loop)
        self.timer_thread.daemon = True
        self.timer_thread.start()

    def _timer_loop(self):
        while self.running:
            current_time = time.time()
            retransmit = []

            timeout = self._calculate_timeout()

            for seq, (packet, sent_time, retries) in list(self.send_buffer.items()):
                if current_time - sent_time > timeout:
                    if retries < 3:
                        retransmit.append(seq)
                    else:
                        del self.send_buffer[seq]
                        if self.loss_callback:
                            print(f"Packet {seq} dropped after {retries} retries")
                        
            for seq in retransmit:
                packet, sent_time, retries = self.send_buffer[seq]
                print(f"Retransmitting packet {seq} (retry {retries + 1}, RTO={timeout:.3f}s)")
                self._send_raw(packet.serialize(), self.peer_addr)
                self.send_buffer[seq] = (packet, current_time, retries + 1)
                self.congestion.on_timeout()
                
            time.sleep(0.1)

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
        current_time = time.time()

        for seq in list(self.send_buffer.keys()):
            if seq < ack_num:
                if seq in self.sent_times:
                    rtt_sample = current_time - self.sent_times[seq]

                    if self.min_rtt <= rtt_sample <= self.max_rtt:
                        self._update_rtt(rtt_sample)

                    del self.sent_times[seq]

                del self.send_buffer[seq]

        self.congestion.on_ack_received()
        self.window_size = self.congestion.get_window_size()
        self.timeout_interval = self._calculate_timeout()
    
    def _update_rtt(self, sample: float):
        if self.rtt_avg == 0:
            self.rtt_avg = sample
            self.rtt_dev = sample / 2
        else:
            self.rtt_dev = (1 - self.rtt_beta) * self.rtt_dev + \
                          self.rtt_beta * abs(sample - self.rtt_avg)
            self.rtt_avg = (1 - self.rtt_alpha) * self.rtt_avg + \
                          self.rtt_alpha * sample
        
        self.rtt_samples.append(sample)
        if len(self.rtt_samples) > 10:
            self.rtt_samples.pop(0)
        
        if len(self.rtt_samples) % 5 == 0:
            print(f"RTT: avg={self.rtt_avg:.3f}s, dev={self.rtt_dev:.3f}s, "
                  f"samples={len(self.rtt_samples)}")

    def _calculate_timeout(self) -> float:
        timeout = self.rtt_avg + 4 * max(self.rtt_dev, 0.01)
        
        timeout = max(timeout, 0.5)   # Mínimo 500ms
        timeout = min(timeout, 10.0)  # Máximo 10s
        
        return timeout
    
    def get_congestion_stats(self):
        if hasattr(self, 'congestion'):
            return {
                'cwnd': self.congestion.cwnd,
                'ssthresh': self.congestion.ssthresh,
                'state': self.congestion.state,
                'window': self.window_size,
                'dup_acks': self.congestion.dup_ack_count,
                'rtt_avg': getattr(self.congestion, 'rtt_avg', 0),
                'timeout': getattr(self.congestion, 'timeout_interval', 0)
            }
        return {}


    def _handle_data(self, packet: TRUPacket, addr: Tuple[str, int]):
        if packet.seq_num in self.received_segments:
            self.receive_stats['duplicates'] += 1
            ack_packet = TRUPacket(
                seq_num=0,
                ack_num=packet.seq_num + len(packet.data),
                packet_type=PacketType.ACK,
                timestamp=time.time()
            )
            self._send_raw(ack_packet.serialize(), addr)
            self.receive_stats['acks_sent'] += 1
            return

        self.receive_buffer[packet.seq_num] = packet.data
        self.received_segments.add(packet.seq_num)
        self.receive_stats['received'] += 1

        ack_packet = TRUPacket(
            seq_num=0,
            ack_num=packet.seq_num + len(packet.data),
            packet_type=PacketType.ACK,
            timestamp=time.time()
        )
        self._send_raw(ack_packet.serialize(), addr)
        self.receive_stats['acks_sent'] += 1

        self._deliver_data()
    
    def get_rtt_stats(self) -> dict:
        if not self.rtt_samples:
            return {
                'avg': 0,
                'min': 0,
                'max': 0,
                'dev': 0,
                'timeout': self.timeout_interval,
                'samples': 0
            }
        
        return {
            'avg': self.rtt_avg,
            'min': min(self.rtt_samples) if self.rtt_samples else 0,
            'max': max(self.rtt_samples) if self.rtt_samples else 0,
            'dev': self.rtt_dev,
            'timeout': self._calculate_timeout(),
            'samples': len(self.rtt_samples)
        }

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
            self.next_seq += 1
            self._send_raw(fin_packet.serialize(), self.peer_addr)

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
        if self.timer_thread:
            self.timer_thread.join(timeout=1.0)

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
        self._send_raw(syn_packet.serialize(), self.peer_addr)

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

            sent_time = time.time()
            self.sent_times[packet.seq_num] = sent_time

            self.send_buffer[packet.seq_num] = (packet, sent_time, 0)
            self._send_raw(packet.serialize(), self.peer_addr)
            
            self.next_seq += len(segment)
            
            self.congestion.on_packet_sent()
            
            if progress_cb:
                progress_cb(i+1, total_segments)
                
        start_time = time.time()
        timeout = self._calculate_timeout() * 3
        while self.send_buffer and time.time() - start_time < timeout:
            time.sleep(0.1)
        
        success = len(self.send_buffer) == 0
        if success:
            self.sent_times.clear()

        return success
        
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

    def do_key_exchange_as_client(self) -> bool:
        try:
            g, p, private = self.crypto.generate_dh_params()
            public = self.crypto.compute_dh_public(g, p, private)
            
            dh_data = f"DH:{g}:{p}:{public}".encode()
            packet = TRUPacket(
                seq_num=self.next_seq,
                packet_type=PacketType.DATA,
                data=dh_data,
                timestamp=time.time()
            )
            self.next_seq += 1
            self._send_raw(packet.serialize(), self.peer_addr)
            
            start_time = time.time()
            while time.time() - start_time < 5.0:
                try:
                    self.sock.settimeout(1.0)
                    data, addr = self.sock.recvfrom(1024)
                    packet = TRUPacket.deserialize(data)
                    
                    if packet.data.startswith(b"DH:"):
                        parts = packet.data.decode().split(':')
                        server_public = int(parts[1])
                        
                        shared = self.crypto.compute_dh_shared(server_public, private, p)
                        self.encryption_key, _ = self.crypto.derive_key(shared)
                        self.encryption_enabled = True
                        return True
                        
                except socket.timeout:
                    continue
                    
        except Exception as e:
            print(f"Key exchange error: {e}")
            
        return False
        
    def do_key_exchange_as_server(self):
        try:
            start_time = time.time()
            while time.time() - start_time < 5.0:
                try:
                    self.sock.settimeout(1.0)
                    data, addr = self.sock.recvfrom(1024)
                    packet = TRUPacket.deserialize(data)
                    
                    if packet.data.startswith(b"DH:"):
                        parts = packet.data.decode().split(':')
                        g = int(parts[1])
                        p = int(parts[2])
                        client_public = int(parts[3])
                        
                        private = self.crypto.generate_dh_params()[2]
                        server_public = self.crypto.compute_dh_public(g, p, private)
                        
                        shared = self.crypto.compute_dh_shared(client_public, private, p)
                        self.encryption_key, _ = self.crypto.derive_key(shared)
                        self.encryption_enabled = True
                        
                        response = f"DH:{server_public}".encode()
                        resp_packet = TRUPacket(
                            seq_num=self.next_seq,
                            packet_type=PacketType.DATA,
                            data=response,
                            timestamp=time.time()
                        )
                        self.next_seq += 1
                        self._send_raw(resp_packet.serialize(), addr)
                        return
                        
                except socket.timeout:
                    continue
                    
        except Exception as e:
            print(f"Key exchange error: {e}")