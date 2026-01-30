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

        # RTT
        self.rtt_samples = []  # Store RTT samples for moving average
        self.rtt_avg = 0.0     # Initial RTT estimate (seconds)
        self.rtt_dev = 0.1    # Initial RTT deviation
        self.rtt_alpha = 0.125  # Weight for moving average (RFC 6298)
        self.rtt_beta = 0.25   # Weight for deviation (RFC 6298)
        self.min_rtt = 0.001     # Minimum RTT (100ms)
        self.max_rtt = 2.0     # Maximum RTT (2 seconds)

        self.sent_times = {}

        self.timeout_interval = 1.0

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

        # seq numbers (definir antes de ack_num)
        self.base_seq = random.randint(0, 2**31 - 1)
        self.next_seq = self.base_seq
        self.ack_num = self.base_seq
        self.ack_sum = 0

        self.send_window = []
        self.received_segments = set()
        
        # status connection
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
        self.receiver_thread = None
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
                if not data:
                    continue
                try:
                    packet = TRUPacket.deserialize(data)
                except Exception as e:
                    continue
                self._process_packet(packet, addr)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Receiver erro: {e}")
                if self.running:
                    time.sleep(0.1)
                continue

    def _process_packet(self, packet: TRUPacket, addr: Tuple[str, int]):
        if not self.peer_addr:
            print(f"[PROCESS] Definindo peer_addr para {addr}")
            self.peer_addr = addr

        if self.loss_callback and self.loss_callback(packet.seq_num):
            print(f"Packet {packet.seq_num} dropped")
            return

        print(f"[PROCESS] Processando pacote tipo={packet.packet_type}, seq={packet.seq_num}, ack={packet.ack_num}")

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
        else:
            print(f"[PROCESS] Tipo de pacote desconhecido: {packet.packet_type}")

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
        self._send_raw(syn_ack_packet, addr)
        
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
            self._send_raw(ack_packet, self.peer_addr)
            
            self.connected = True
            self.base_seq = packet.ack_num
            self.next_seq = packet.ack_num
            print(f"Connection established with {self.peer_addr}")

    def _handle_ack(self, packet: TRUPacket):
        print(f"[HANDLE_ACK] Recebido ACK para pacote {packet.ack_num}")
        ack_num = packet.ack_num
        current_time = time.time()

        acked_seqs = []
        for seq in list(self.send_buffer.keys()):
            if seq < ack_num:
                if seq in self.sent_times:
                    rtt_sample = current_time - self.sent_times[seq]
                    print(f"[HANDLE_ACK] Calculando RTT para seq={seq}: {rtt_sample:.3f}s")

                    if self.min_rtt <= rtt_sample <= self.max_rtt:
                        self._update_rtt(rtt_sample)

                    del self.sent_times[seq]

                del self.send_buffer[seq]
                acked_seqs.append(seq)
        
        if acked_seqs:
            print(f"[HANDLE_ACK] ACKs confirmados: {acked_seqs}")
        else:
            print(f"[HANDLE_ACK] Nenhum pacote confirmado por este ACK")

        self.congestion.on_ack_received()
        self.window_size = self.congestion.get_window_size()
        self.timeout_interval = self._calculate_timeout()
    
    def _update_rtt(self, sample: float):
        print(f"[UPDATE_RTT] Nova amostra RTT: {sample:.6f}s")

        if self.rtt_avg == 0:
            self.rtt_avg = sample
            self.rtt_dev = sample / 2
            print(f"[UPDATE_RTT] Primeira amostra: avg={self.rtt_avg:.6f}, dev={self.rtt_dev:.6f}")
        else:
            error = sample - self.rtt_avg
            self.rtt_dev = (1 - self.rtt_beta) * self.rtt_dev + self.rtt_beta * abs(error)
            self.rtt_avg = (1 - self.rtt_alpha) * self.rtt_avg + self.rtt_alpha * sample
            print(f"[UPDATE_RTT] Atualizado: avg={self.rtt_avg:.6f}, dev={self.rtt_dev:.6f}, erro={error:.6f}")
        
        self.rtt_samples.append(sample)
        if len(self.rtt_samples) > 10:
            self.rtt_samples.pop(0)
        
        print(f"[UPDATE_RTT] Total de amostras: {len(self.rtt_samples)}")
        
    

    def _calculate_timeout(self) -> float:
        timeout = self.rtt_avg + 4 * max(self.rtt_dev, 0.01)
        
        timeout = max(timeout, 0.1)   # Mínimo 100ms
        timeout = min(timeout, 10.0)  # Máximo 10s

        print(f"[CALC_TIMEOUT] RTT_avg={self.rtt_avg:.6f}, RTT_dev={self.rtt_dev:.6f}, timeout={timeout:.3f}s")
        
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
        print(f"[HANDLE_DATA] Recebido pacote DATA, seq={packet.seq_num}, tamanho={len(packet.data)}")
        
        if packet.seq_num in self.received_segments:
            print(f"[HANDLE_DATA] Pacote duplicado {packet.seq_num}")
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
        print(f"[HANDLE_DATA] Enviando ACK para seq={packet.seq_num + len(packet.data)}")

        self._send_raw(ack_packet.serialize(), addr)
        self.receive_stats['acks_sent'] += 1

        self._deliver_data()
    
    def get_rtt_stats(self) -> dict:
        print(f"[GET_RTT_STATS] Chamado. Amostras: {self.rtt_samples}, média: {self.rtt_avg:.6f}")

        if not self.rtt_samples:
            return {
                'avg': 0,
                'min': 0,
                'max': 0,
                'dev': self.rtt_dev,
                'timeout': self.timeout_interval,
                'samples': 0
            }
        
        min_rtt = min(self.rtt_samples)
        max_rtt = max(self.rtt_samples)

        return {
            'avg': self.rtt_avg,
            'min': min_rtt,
            'max': max_rtt,
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
        self._send_raw(fin_ack_packet, self.peer_addr)
        
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
            self._send_raw(packet, self.peer_addr)

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

    def _send_raw(self, packet_or_bytes, addr: Tuple[str, int]):
        try:
            if isinstance(packet_or_bytes, TRUPacket):
                packet_or_bytes.checksum = packet_or_bytes.calculate_checksum()
                data = packet_or_bytes.serialize()
            else:
                data = packet_or_bytes
                
            self.sock.sendto(data, addr)
        except Exception as e:
            print(f"Erro ao enviar dados: {e}")

    def connect(self, host: str, port: int) -> bool:
        self.peer_addr = (host, port)
        print(f"[CONNECT] Conectando a {host}:{port}")

        for attempt in range(3):
            print(f"[CONNECT] Tentativa {attempt + 1}/3")

            #SYN
            syn_packet = TRUPacket(
                seq_num=self.base_seq,
                packet_type=PacketType.SYN, 
                timestamp=time.time()
            )
            self.next_seq += 1
            print(f"[CONNECT] Enviando SYN, seq={syn_packet.seq_num}")
            self._send_raw(syn_packet.serialize(), self.peer_addr)

            #espera SYN-ACK
            self.sock.settimeout(2.0)

            try:
                data, addr = self.sock.recvfrom(1024)
                print(f"[CONNECT] Recebido {len(data)} bytes de {addr}")

                try:
                    packet = TRUPacket.deserialize(data)
                except ValueError as e:
                    print(f"[CONNECT] Erro deserializando: {e}")
                    continue

                print(f"[CONNECT] Pacote recebido: tipo={packet.packet_type}, seq={packet.seq_num}, ack={packet.ack_num}")

                if (packet.packet_type == PacketType.SYN_ACK and
                    packet.ack_num == syn_packet.seq_num + 1):

                    print(f"[CONNECT] SYN-ACK recebido, ack={packet.ack_num}, seq={packet.seq_num}")

                    ack_packet = TRUPacket(
                        seq_num=packet.ack_num,
                        ack_num=packet.seq_num + 1,
                        packet_type=PacketType.ACK,
                        timestamp=time.time()
                    )
                    self._send_raw(ack_packet.serialize(), self.peer_addr)
                    print(f"[CONNECT] Enviando ACK, seq={ack_packet.seq_num}, ack={ack_packet.ack_num}")

                    self.connected = True
                    self.next_seq = packet.ack_num
                    print("[CONNECT] Handshake completado. Conectado a {self.peer_addr}")
                    return True
                else:
                    print(f"[CONNECT] Pacote não é SYN-ACK correto")

            except socket.timeout:
                print("[CONNECT] Timeout tentativa {attempt + 1}")
                continue
            except Exception as e:
                print(f"[CONNECT] Erro: {e}")
                continue
        
        print("[CONNECT] Falha no handshake - timeout")
        return True

    def accept(self) -> bool:
        if not self.is_server:
            return False
        
        print("[ACCEPT] Aguardando conexão...")
        self.sock.settimeout(30.0)

        try:
            data, addr = self.sock.recvfrom(1024)
            print(f"[ACCEPT] Recebido {len(data)} bytes de {addr}")

            try:
                packet = TRUPacket.deserialize(data)
            except ValueError as e:
                print(f"[ACCEPT] Erro deserializando SYN: {e}")
                return False

            print(f"[ACCEPT] Pacote recebido: tipo={packet.packet_type}, seq={packet.seq_num}")
            
            if packet.packet_type == PacketType.SYN:
                print(f"[ACCEPT] SYN recebido de {addr}, seq={packet.seq_num}")
                self.peer_addr = addr

                syn_ack_packet = TRUPacket(
                    seq_num=self.next_seq,
                    ack_num=packet.seq_num + 1,
                    packet_type=PacketType.SYN_ACK,
                    timestamp=time.time()
                )
                self.next_seq += 1
                print(f"[ACCEPT] Enviando SYN-ACK, seq={syn_ack_packet.seq_num}, ack={syn_ack_packet.ack_num}")
                self._send_raw(syn_ack_packet.serialize(), addr)

                # PARAR temporariamente a thread de recepção para não interferir
                if self.running:
                    self.running = False
                    if self.receiver_thread:
                        self.receiver_thread.join(timeout=1.0)
                
                self.sock.settimeout(10.0)
                try:
                    data, _ = self.sock.recvfrom(1024)
                    ack_packet = TRUPacket.deserialize(data)

                    print(f"[ACCEPT] Pacote ACK recebido: seq={ack_packet.seq_num}, ack={ack_packet.ack_num}")
                    syn_ack_packet = TRUPacket(
                        seq_num=self.next_seq,
                        ack_num=packet.seq_num + 1,
                        packet_type=PacketType.SYN_ACK,
                        timestamp=time.time()
                    )
                    self.next_seq += 1
                    self._send_raw(syn_ack_packet, addr)
                    
                    if (ack_packet.packet_type == PacketType.ACK and
                        ack_packet.ack_num == syn_ack_packet.seq_num + 1):

                        self.connected = True
                        self.next_seq = ack_packet.seq_num
                        print("[ACCEPT] Handshake completado com sucesso, Cliente {addr} conectado")
                        
                        self.running = True
                        self.receiver_thread = threading.Thread(target=self._receiver_loop)
                        self.receiver_thread.daemon = True
                        self.receiver_thread.start()

                        return True
                    else:
                        print(f"[ACCEPT] Pacote não é ACK: tipo={ack_packet.packet_type}")
                        
                except socket.timeout:
                    print("[ACCEPT] Timeout esperando ACK")
                except ValueError as e:
                    print(f"[ACCEPT] Erro deserializando ACK: {e}")
            else:
                print(f"[ACCEPT] Pacote não é SYN")

        except socket.timeout:
            print("[ACCEPT] Timeout aguardando SYN")
        except Exception as e:
            print(f"Accept error: {e}")

        return False
                        if ack_packet.packet_type == PacketType.ACK:
                            self.connected = True
                            self.base_seq = ack_packet.seq_num
                            self.ack_num = ack_packet.seq_num  # próximo seq esperado do cliente
                            return True
                            
                    except socket.timeout:
                        # Timeout esperando ACK; voltar a esperar novo SYN (resetar timeout)
                        self.sock.settimeout(1.0)
                        continue
                    except ValueError:
                        # Pacote inválido (ex.: pequeno demais); ignorar e voltar a esperar SYN
                        self.sock.settimeout(1.0)
                        continue
            except socket.timeout:
                # Timeout esperando SYN; continuar ouvindo (não encerrar)
                continue
            except ValueError:
                # Pacote inválido (ICMP, lixo, etc.); ignorar e continuar ouvindo
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
            print("[KEY-EXCHANGE] Iniciando troca de chaves (cliente)")
            g, p, private = self.crypto.generate_dh_params()
            print(f"[KEY-EXCHANGE] Parâmetros DH: g={g}, p={p}, private={private}")
            public = self.crypto.compute_dh_public(g, p, private)
            
            dh_data = f"DH:{g}:{p}:{public}".encode()
            packet = TRUPacket(
                seq_num=self.next_seq,
                packet_type=PacketType.DATA,
                data=dh_data,
                timestamp=time.time()
            )
            self.next_seq += 1
            print(f"[KEY-EXCHANGE] Enviando chave pública: {public}")
            self._send_raw(packet.serialize(), self.peer_addr)
            
            start_time = time.time()
            self.sock.settimeout(5.0)

            while time.time() - start_time < 5.0:
                try:
                    data, addr = self.sock.recvfrom(1024)
                    packet = TRUPacket.deserialize(data)
                    
                    if packet.data and packet.data.startswith(b"DH:"):
                        print(f"[KEY-EXCHANGE] Resposta recebida: {packet.data[:50]}...")
                        parts = packet.data.decode().split(':')
                        server_public = int(parts[1])
                        
                        shared = self.crypto.compute_dh_shared(server_public, private, p)
                        print(f"[KEY-EXCHANGE] Segredo compartilhado calculado")
                        self.encryption_key, _ = self.crypto.derive_key(shared)
                        self.encryption_enabled = True
                        print("[KEY-EXCHANGE] Troca de chaves completada com sucesso")
                        return True
                    else:
                        print(f"[KEY-EXCHANGE] Pacote não contém dados DH")
                        
                except socket.timeout:
                    print("[KEY-EXCHANGE] Timeout esperando resposta do servidor")
                    continue
                except Exception as e:
                    print(f"[KEY-EXCHANGE] Erro processando resposta: {e}")

        except Exception as e:
            print(f"Key exchange error: {e}")
            import traceback
            traceback.print_exc()

        print("[KEY-EXCHANGE] Falha na troca de chaves")
        return False
        
    def do_key_exchange_as_server(self):
        try:
            print("[KEY-EXCHANGE] Aguardando troca de chaves do cliente")
            start_time = time.time()
            self.sock.settimeout(10.0)

            while time.time() - start_time < 10.0:
                try:
                    data, addr = self.sock.recvfrom(1024)
                    packet = TRUPacket.deserialize(data)
                    
                    if packet.data and packet.data.startswith(b"DH:"):
                        print(f"[KEY-EXCHANGE] Dados DH recebidos: {packet.data[:50]}...")
                        parts = packet.data.decode().split(':')
                        g = int(parts[1])
                        p = int(parts[2])
                        client_public = int(parts[3])

                        print(f"[KEY-EXCHANGE] Parâmetros recebidos: g={g}, p={p}, client_public={client_public}")
                        
                        private = self.crypto.generate_dh_params()[2]
                        server_public = self.crypto.compute_dh_public(g, p, private)
                        
                        shared = self.crypto.compute_dh_shared(client_public, private, p)
                        print(f"[KEY-EXCHANGE] Segredo compartilhado calculado")
                        self.encryption_key, _ = self.crypto.derive_key(shared)
                        self.encryption_enabled = True
                        # Cliente enviou 1 "segmento" (DH); próximo dado terá seq_num = packet.seq_num + 1
                        self.ack_num = packet.seq_num + 1
                        
                        response = f"DH:{server_public}".encode()
                        resp_packet = TRUPacket(
                            seq_num=self.next_seq,
                            packet_type=PacketType.DATA,
                            data=response,
                            timestamp=time.time()
                        )
                        self.next_seq += 1
                        print(f"[KEY-EXCHANGE] Enviando chave pública do servidor: {server_public}")
                        self._send_raw(resp_packet.serialize(), addr)
                        print("[KEY-EXCHANGE] Troca de chaves completada com sucesso")
                        return
                    else:
                        print(f"[KEY-EXCHANGE] Pacote não contém dados DH")

                        
                except socket.timeout:
                    print("[KEY-EXCHANGE] Timeout aguardando dados DH do cliente")
                    continue
                except Exception as e:
                    print(f"[KEY-EXCHANGE] Erro processando dados: {e}")
                    import traceback
                    traceback.print_exc()
                    
        except Exception as e:
            print(f"Key exchange error: {e}")
            import traceback
            traceback.print_exc()
