import socket
import time
import threading
import struct
import os
from packet import TRUPacket, PacketType
from typing import Optional, Tuple, Callable, List
from congestion import CongestionControl
from crypto import TRUCrypto
import random
import statistics
import sys

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
        self.iv = None  # Vetor de inicialização

        # RTT
        self.rtt_samples = []
        self.rtt_avg = 0.0
        self.rtt_dev = 0.1
        self.rtt_alpha = 0.125
        self.rtt_beta = 0.25
        self.min_rtt = 0.0001
        self.max_rtt = 2.0

        self.sent_times = {}
        self.timeout_interval = 1.0
        self.monitoring_active = False

        self.receive_stats = {
            'received': 0,
            'duplicates': 0,
            'acks_sent': 0
        }

        # Sequências
        self.base_seq = random.randint(0, 2**31 - 1)
        self.next_seq = self.base_seq
        self.ack_num = self.base_seq

        # Socket UDP
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if is_server:
            self.sock.bind((host, port))
        
        self.sock.settimeout(1.0)

        # Estado da conexão
        self.connected = False
        self.peer_addr = None
        
        # Buffers
        self.send_buffer = {}
        self.receive_buffer = {}
        self.received_segments = set()
        
        # Controle de janela
        self.window_size = 4
        self.congestion = CongestionControl()
        
        # Controle de threads
        self.receiver_thread = None
        self.timer_thread = None
        self.running = False
        
        # Fila para aplicação
        self.app_queue = []
        
        # Eventos para sincronização
        self.handshake_event = threading.Event()
        self.key_exchange_event = threading.Event()
        
        # Flag para controle interno
        self._handshake_in_progress = False
        
        # Estado de troca de chaves
        self.dh_private_key = None
        self.dh_public_key = None
        self.dh_prime = None
        self.dh_generator = None
        self.peer_public_key = None

    def start(self):
        if self.running:
            return
        
        self.running = True
        
        # Iniciar thread receiver
        self.receiver_thread = threading.Thread(target=self._receiver_loop)
        self.receiver_thread.daemon = True
        self.receiver_thread.start()
        
        # Iniciar thread timer
        self.timer_thread = threading.Thread(target=self._timer_loop)
        self.timer_thread.daemon = True
        self.timer_thread.start()
        
        print(f"[START] Threads iniciadas (is_server={self.is_server})")

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
                        print(f"Packet {seq} dropped after {retries} retries")

            for seq in retransmit:
                packet, sent_time, retries = self.send_buffer[seq]
                print(f"Retransmitting packet {seq} (retry {retries + 1}, RTO={timeout:.3f}s)")
                self._send_raw(packet.serialize(), self.peer_addr)
                self.send_buffer[seq] = (packet, current_time, retries + 1)
                self.congestion.on_timeout()

            time.sleep(0.1)

    def _receiver_loop(self):
        print(f"[RECEIVER_LOOP] Iniciado (is_server={self.is_server})")
        
        while self.running:
            try:
                data, addr = self.sock.recvfrom(2048)
                if not data:
                    continue
                
                if not self.peer_addr:
                    print(f"[RECEIVER] Primeiro pacote de {addr}, definindo como peer_addr")
                    self.peer_addr = addr
                elif addr != self.peer_addr:
                    print(f"[RECEIVER] Pacote de endereço desconhecido: {addr}, esperado: {self.peer_addr}")
                    continue
                
                try:
                    packet = TRUPacket.deserialize(data)
                    print(f"[RECEIVER] Pacote recebido: tipo={packet.packet_type}, seq={packet.seq_num}, ack={packet.ack_num}")
                    
                    # Processar pacote
                    self._process_packet(packet, addr)
                    
                except Exception as e:
                    print(f"[RECEIVER] Erro ao processar pacote: {e}")
                    continue
                    
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[RECEIVER] Erro geral: {e}")
                    time.sleep(0.1)
                continue

    def _process_packet(self, packet: TRUPacket, addr: Tuple[str, int]):
        print(f"[PROCESS] Pacote de {addr}: tipo={packet.packet_type}, seq={packet.seq_num}, ack={packet.ack_num}")

        if self.loss_callback and self.loss_callback(packet.seq_num):
            print(f"Packet {packet.seq_num} dropped (loss callback)")
            return

        # Verificar checksum
        if packet.checksum != packet.calculate_checksum():
            print(f"[PROCESS] Checksum inválido, descartando")
            return

        if packet.packet_type == PacketType.SYN:
            self._handle_syn(packet, addr)
        elif packet.packet_type == PacketType.SYN_ACK:
            self._handle_syn_ack(packet)
        elif packet.packet_type == PacketType.ACK:
            self._handle_ack(packet)
        elif packet.packet_type == PacketType.DATA:
            self._handle_data(packet, addr)
        elif packet.packet_type == PacketType.FIN:
            self._handle_fin(packet)
        elif packet.packet_type == PacketType.FIN_ACK:
            self._handle_fin_ack()
        elif packet.packet_type == PacketType.KEY_EXCHANGE:
            self._handle_key_exchange(packet, addr)
        elif packet.packet_type == PacketType.KEY_RESPONSE:
            self._handle_key_response(packet)
        else:
            print(f"[PROCESS] Tipo de pacote desconhecido: {packet.packet_type}")

    def _handle_syn(self, packet: TRUPacket, addr: Tuple[str, int]):
        print(f"[HANDLE_SYN] Recebido SYN de {addr}, seq={packet.seq_num}")
        
        if self.connected:
            print(f"[HANDLE_SYN] Já conectado, ignorando")
            return
        
        self.peer_addr = addr
        
        # Enviar SYN-ACK
        syn_ack_packet = TRUPacket(
            seq_num=self.next_seq,
            ack_num=packet.seq_num + 1,
            packet_type=PacketType.SYN_ACK,
            window=self.window_size,
            checksum=0,
            timestamp=time.time(),
            iv=b'',
            data=b''
        )
        syn_ack_packet.checksum = syn_ack_packet.calculate_checksum()
        self.next_seq += 1
        
        print(f"[HANDLE_SYN] Enviando SYN-ACK, seq={syn_ack_packet.seq_num}, ack={syn_ack_packet.ack_num}")
        self._send_raw(syn_ack_packet, addr)
        
        # Marcar que estamos em handshake
        self._handshake_in_progress = True

    def _handle_syn_ack(self, packet: TRUPacket):
        print(f"[HANDLE_SYN_ACK] Recebido SYN-ACK, seq={packet.seq_num}, ack={packet.ack_num}")
        
        if self.connected:
            print(f"[HANDLE_SYN_ACK] Já conectado, ignorando")
            return
        
        # Verificar se o ACK corresponde ao nosso SYN
        expected_ack = self.base_seq + 1
        if packet.ack_num == expected_ack:
            print(f"[HANDLE_SYN_ACK] ACK correto, enviando ACK final")
            
            # Enviar ACK para completar handshake
            ack_packet = TRUPacket(
                seq_num=packet.ack_num,
                ack_num=packet.seq_num + 1,
                packet_type=PacketType.ACK,
                window=self.window_size,
                checksum=0,
                timestamp=time.time(),
                iv=b'',
                data=b''
            )
            ack_packet.checksum = ack_packet.calculate_checksum()
            
            print(f"[HANDLE_SYN_ACK] Enviando ACK, seq={ack_packet.seq_num}, ack={ack_packet.ack_num}")
            self._send_raw(ack_packet, self.peer_addr)
            
            # Atualizar estado
            self.connected = True
            self.next_seq = packet.ack_num
            self.ack_num = packet.seq_num + 1
            
            print(f"[HANDLE_SYN_ACK] Conexão estabelecida com {self.peer_addr}")
            
            # Sinalizar que o handshake está completo
            self.handshake_event.set()
        else:
            print(f"[HANDLE_SYN_ACK] ACK incorreto: esperado {expected_ack}, recebido {packet.ack_num}")

    def _handle_ack(self, packet: TRUPacket):
        print(f"[HANDLE_ACK] Recebido ACK para ack_num={packet.ack_num}")
        
        # Verificar se é ACK do handshake (servidor)
        if not self.connected and self._handshake_in_progress:
            print(f"[HANDLE_ACK] ACK do handshake recebido, completando conexão")
            self.connected = True
            self._handshake_in_progress = False
            self.handshake_event.set()
            return
        
        # Processar ACK de dados
        ack_num = packet.ack_num
        current_time = time.time()
        acked_seqs = []

        for seq in list(self.send_buffer.keys()):
            if seq < ack_num:
                if seq in self.sent_times:
                    rtt_sample = current_time - self.sent_times[seq]
                    print(f"[HANDLE_ACK] RTT para seq={seq}: {rtt_sample:.6f}s")
                    
                    if self.min_rtt <= rtt_sample <= self.max_rtt:
                        self._update_rtt(rtt_sample)
                    elif self.rtt_avg == 0 and rtt_sample > 0:
                        # Aceitar primeira amostra mesmo se fora dos limites
                        self._update_rtt(rtt_sample)
                    
                    del self.sent_times[seq]
                
                del self.send_buffer[seq]
                acked_seqs.append(seq)
        
        if acked_seqs:
            print(f"[HANDLE_ACK] ACKs confirmados: {acked_seqs}")
            self.congestion.on_ack_received()
            self.window_size = self.congestion.get_window_size()
            self.timeout_interval = self._calculate_timeout()
        else:
            print(f"[HANDLE_ACK] Nenhum pacote confirmado por este ACK")

    def _handle_data(self, packet: TRUPacket, addr: Tuple[str, int]):
        print(f"[HANDLE_DATA] Recebido DATA, seq={packet.seq_num}, tamanho={len(packet.data)}")
        
        # Ajustar ack_num se for o primeiro pacote
        if len(self.received_segments) == 0 and packet.seq_num != self.ack_num:
            print(f"[HANDLE_DATA] Ajustando ack_num de {self.ack_num} para {packet.seq_num}")
            self.ack_num = packet.seq_num
        
        # Verificar duplicata
        if packet.seq_num in self.received_segments:
            print(f"[HANDLE_DATA] Pacote duplicado {packet.seq_num}")
            self.receive_stats['duplicates'] += 1
            
            # Enviar ACK mesmo para duplicata
            ack_num = packet.seq_num + len(packet.data)
            ack_packet = TRUPacket(
                seq_num=0,
                ack_num=ack_num,
                packet_type=PacketType.ACK,
                window=self.window_size,
                checksum=0,
                timestamp=time.time(),
                iv=b'',
                data=b''
            )
            ack_packet.checksum = ack_packet.calculate_checksum()
            self._send_raw(ack_packet, addr)
            self.receive_stats['acks_sent'] += 1
            return
        
        # Se criptografia estiver habilitada, descriptografar os dados
        data_to_store = packet.data
        if self.encryption_enabled and self.encryption_key is not None and packet.iv:
            try:
                decrypted_data = self.crypto.decrypt_data(packet.data, self.encryption_key, packet.iv)
                data_to_store = decrypted_data
                print(f"[HANDLE_DATA] Dados descriptografados: {len(decrypted_data)} bytes")
            except Exception as e:
                print(f"[HANDLE_DATA] Erro ao descriptografar: {e}")
        
        # Armazenar dados
        self.receive_buffer[packet.seq_num] = data_to_store
        self.received_segments.add(packet.seq_num)
        self.receive_stats['received'] += 1
        
        # Entregar dados em ordem
        self._deliver_data()
        
        # Enviar ACK
        ack_num = packet.seq_num + len(packet.data)
        ack_packet = TRUPacket(
            seq_num=0,
            ack_num=ack_num,
            packet_type=PacketType.ACK,
            window=self.window_size,
            checksum=0,
            timestamp=time.time(),
            iv=b'',
            data=b''
        )
        ack_packet.checksum = ack_packet.calculate_checksum()
        print(f"[HANDLE_DATA] Enviando ACK para ack_num={ack_num}")
        self._send_raw(ack_packet, addr)
        self.receive_stats['acks_sent'] += 1

    def _handle_key_exchange(self, packet: TRUPacket, addr: Tuple[str, int]):
        print(f"[KEY_EXCHANGE] Recebido pedido de troca de chaves do cliente")
        
        try:
            if len(packet.data) < 24:
                print(f"[KEY_EXCHANGE] Dados insuficientes para troca de chaves")
                return
                
            g, p, client_public = struct.unpack('!QQQ', packet.data[:24])
            print(f"[KEY_EXCHANGE] Parâmetros recebidos: g={g}, p={p}, client_public={client_public}")
            
            server_private = random.randint(1, p-2)
            
            server_public = self.crypto.compute_dh_public(g, p, server_private)
            
            shared_secret = self.crypto.compute_dh_shared(client_public, server_private, p)
            
            encryption_key, salt = self.crypto.derive_key(shared_secret)
            self.encryption_key = encryption_key
            self.encryption_enabled = True
            
            self.iv = os.urandom(16)
            
            print(f"[KEY_EXCHANGE] Chave derivada com sucesso (tamanho: {len(encryption_key)} bytes)")
            print(f"[KEY_EXCHANGE] IV gerado: {self.iv.hex()[:16]}...")
            
            if not self.crypto.test_encryption(encryption_key):
                print(f"[KEY_EXCHANGE] Teste de criptografia falhou")
                return
            
            response_data = struct.pack('!Q', server_public) + struct.pack('!H', len(self.iv)) + self.iv
            
            key_response = TRUPacket(
                seq_num=self.next_seq,
                ack_num=packet.seq_num + 1,
                packet_type=PacketType.KEY_RESPONSE,
                window=self.window_size,
                checksum=0,
                timestamp=time.time(),
                iv=b'',
                data=response_data
            )
            key_response.checksum = key_response.calculate_checksum()
            self.next_seq += 1
            
            print(f"[KEY_EXCHANGE] Enviando resposta de troca de chaves")
            self._send_raw(key_response, addr)

            print(f"[KEY_EXCHANGE] Troca de chaves completada no servidor")
            self.key_exchange_event.set()
            
        except Exception as e:
            print(f"[KEY_EXCHANGE] Erro durante troca de chaves: {e}")
            import traceback
            traceback.print_exc()

    def _handle_key_response(self, packet: TRUPacket):
        print(f"[KEY_RESPONSE] Recebida resposta de troca de chaves do servidor")
        
        try:
            if len(packet.data) < 8:  # 2 inteiros de 4 bytes cada
                print(f"[KEY_RESPONSE] Dados insuficientes")
                return
                
            server_public, iv_length = struct.unpack('!II', packet.data[:8])
            
            # Extrair IV
            if len(packet.data) >= 8 + iv_length:
                self.iv = packet.data[8:8+iv_length]
            else:
                print(f"[KEY_RESPONSE] IV incompleto ou ausente")
                return
            
            # Calcular segredo compartilhado usando a chave pública do servidor
            if not all([self.dh_private_key, self.dh_prime, self.dh_generator]):
                print(f"[KEY_RESPONSE] Parâmetros DH não inicializados")
                return
                
            shared_secret = self.crypto.compute_dh_shared(server_public, self.dh_private_key, self.dh_prime)
            
            # Derivar chave de criptografia
            encryption_key, salt = self.crypto.derive_key(shared_secret)
            self.encryption_key = encryption_key
            self.encryption_enabled = True
            
            print(f"[KEY_RESPONSE] Chave derivada com sucesso (tamanho: {len(encryption_key)} bytes)")
            print(f"[KEY_RESPONSE] IV recebido: {self.iv.hex()[:16]}...")
            
            # Testar criptografia
            if self.crypto.test_encryption(encryption_key):
                print(f"[KEY_RESPONSE] Criptografia testada com sucesso!")
                self.key_exchange_event.set()
            else:
                print(f"[KEY_RESPONSE] Teste de criptografia falhou")
                
        except Exception as e:
            print(f"[KEY_RESPONSE] Erro ao processar resposta: {e}")

    def _handle_fin(self, packet: TRUPacket):
        print(f"[HANDLE_FIN] Recebido FIN, seq={packet.seq_num}")
        
        if not self.connected:
            return
        
        # Enviar FIN-ACK
        fin_ack_packet = TRUPacket(
            seq_num=self.next_seq,
            ack_num=packet.seq_num + 1,
            packet_type=PacketType.FIN_ACK,
            window=self.window_size,
            checksum=0,
            timestamp=time.time(),
            iv=b'',
            data=b''
        )
        fin_ack_packet.checksum = fin_ack_packet.calculate_checksum()
        self.next_seq += 1
        
        self._send_raw(fin_ack_packet, self.peer_addr)
        
        self.connected = False
        print(f"[HANDLE_FIN] Conexão fechada por peer {self.peer_addr}")

    def _handle_fin_ack(self):
        print(f"[HANDLE_FIN_ACK] Recebido FIN-ACK")
        
        if self.connected:
            self.connected = False
            print(f"[HANDLE_FIN_ACK] Conexão fechada com {self.peer_addr}")

    def _deliver_data(self):
        sorted_seqs = sorted(self.receive_buffer.keys())
        
        delivered_count = 0
        for seq in sorted_seqs:
            if seq == self.ack_num:
                data = self.receive_buffer.pop(seq)
                self.app_queue.append(data)
                print(f"[DELIVER_DATA] Entregue pacote seq={seq}, tamanho={len(data)} bytes")
                self.ack_num += len(data)
                delivered_count += 1
            elif seq > self.ack_num:
                break
        
        if delivered_count > 0:
            print(f"[DELIVER_DATA] Total entregue: {delivered_count} pacotes")

    def _update_rtt(self, sample: float):
        print(f"[UPDATE_RTT] Nova amostra: {sample:.6f}s")
        
        if self.rtt_avg == 0:
            self.rtt_avg = sample
            self.rtt_dev = sample / 2
        else:
            error = sample - self.rtt_avg
            self.rtt_dev = (1 - self.rtt_beta) * self.rtt_dev + self.rtt_beta * abs(error)
            self.rtt_avg = (1 - self.rtt_alpha) * self.rtt_avg + self.rtt_alpha * sample
        
        self.rtt_samples.append(sample)
        if len(self.rtt_samples) > 10:
            self.rtt_samples.pop(0)
        
        print(f"[UPDATE_RTT] Média: {self.rtt_avg:.6f}s, Desvio: {self.rtt_dev:.6f}s")

    def _calculate_timeout(self) -> float:
        timeout = self.rtt_avg + 4 * max(self.rtt_dev, 0.01)
        timeout = max(timeout, 0.1)   # Mínimo 100ms
        timeout = min(timeout, 10.0)  # Máximo 10s
        return timeout

    def _send_raw(self, packet_or_bytes, addr: Tuple[str, int]):
        try:
            if isinstance(packet_or_bytes, TRUPacket):
                packet = packet_or_bytes
                packet.checksum = packet.calculate_checksum()
                data = packet.serialize()
            else:
                data = packet_or_bytes
            
            self.sock.sendto(data, addr)
            print(f"[SEND_RAW] Enviados {len(data)} bytes para {addr}")
        except Exception as e:
            print(f"[SEND_RAW] Erro: {e}")

    def connect(self, host: str, port: int) -> bool:
        self.peer_addr = (host, port)
        print(f"[CONNECT] Conectando a {host}:{port}")
        
        if not self.running:
            self.start()
        
        for attempt in range(3):
            print(f"[CONNECT] Tentativa {attempt + 1}/3")
            
            # Enviar SYN
            syn_packet = TRUPacket(
                seq_num=self.base_seq,
                ack_num=0,
                packet_type=PacketType.SYN,
                window=self.window_size,
                checksum=0,
                timestamp=time.time(),
                iv=b'',
                data=b''
            )
            syn_packet.checksum = syn_packet.calculate_checksum()
            
            print(f"[CONNECT] Enviando SYN, seq={syn_packet.seq_num}")
            self._send_raw(syn_packet, self.peer_addr)
            
            # Esperar pelo handshake
            if self.handshake_event.wait(timeout=2.0):
                print(f"[CONNECT] Handshake completado")
                return True
            
            print(f"[CONNECT] Timeout na tentativa {attempt + 1}")
        
        print("[CONNECT] Falha no handshake após 3 tentativas")
        return False

    def accept(self) -> bool:
        if not self.is_server:
            return False
        
        print("[ACCEPT] Aguardando conexão...")
        
        if not self.running:
            self.start()
        
        # Esperar pelo handshake
        if self.handshake_event.wait(timeout=30.0):
            print("[ACCEPT] Conexão aceita")
            return True
        else:
            print("[ACCEPT] Timeout aguardando conexão")
            return False

    def send_data(self, data: bytes, progress_cb=None) -> bool:
        if not self.connected or not self.peer_addr:
            print("[SEND_DATA] Não conectado")
            return False
        
        print(f"[SEND_DATA] Iniciando envio de {len(data)} bytes, criptografia: {self.encryption_enabled}")
        
        # Se criptografia estiver habilitada, criptografar os dados
        if self.encryption_enabled and self.encryption_key is not None and self.iv:
            try:
                encrypted_data, iv = self.crypto.encrypt_data(data, self.encryption_key)
                data = encrypted_data
                print(f"[SEND_DATA] Dados criptografados: {len(encrypted_data)} bytes, IV: {iv.hex()[:16]}...")
            except Exception as e:
                print(f"[SEND_DATA] Erro ao criptografar: {e}")
                return False
        
        segment_size = MSS
        segments = []
        
        # Dividir dados em segmentos
        for i in range(0, len(data), segment_size):
            segment = data[i:i+segment_size]
            segments.append(segment)
        
        total_segments = len(segments)
        print(f"[SEND_DATA] Enviando {total_segments} segmentos, total {len(data)} bytes")
        print(f"[SEND_DATA] Janela atual: {self.window_size}, cwnd: {self.congestion.cwnd}")
        
        # Enviar cada segmento
        for i, segment in enumerate(segments):
            # Esperar se a janela estiver cheia
            while len(self.send_buffer) >= self.window_size:
                print(f"[SEND_DATA] Janela cheia ({len(self.send_buffer)}/{self.window_size}), esperando...")
                time.sleep(0.01)
            
            # Criar pacote com IV (para cada pacote ou usar um IV fixo)
            packet_iv = self.iv if self.encryption_enabled else b''
            
            packet = TRUPacket(
                seq_num=self.next_seq,
                ack_num=0,
                packet_type=PacketType.DATA,
                window=self.window_size,
                checksum=0,
                data=segment,
                timestamp=time.time(),
                iv=packet_iv
            )
            packet.checksum = packet.calculate_checksum()
            
            # Registrar tempo de envio
            sent_time = time.time()
            self.sent_times[packet.seq_num] = sent_time
            self.send_buffer[packet.seq_num] = (packet, sent_time, 0)
            
            print(f"[SEND_DATA] Enviando pacote seq={self.next_seq}, tamanho={len(segment)} bytes")
            self._send_raw(packet, self.peer_addr)
            self.next_seq += len(segment)
            
            self.congestion.on_packet_sent()
            
            if progress_cb:
                progress_cb(i + 1, total_segments)
        
        print(f"[SEND_DATA] Todos os pacotes enviados, aguardando ACKs...")
        
        # Esperar confirmação
        start_time = time.time()
        timeout = self._calculate_timeout() * 3
        
        while self.send_buffer and time.time() - start_time < timeout:
            pending = len(self.send_buffer)
            if pending > 0 and time.time() - start_time > 1.0:
                print(f"[SEND_DATA] Aguardando {pending} pacotes...")
            time.sleep(0.1)
        
        success = len(self.send_buffer) == 0
        
        if success:
            self.sent_times.clear()
            print("[SEND_DATA] Todos os pacotes confirmados")
        else:
            print(f"[SEND_DATA] Timeout: {len(self.send_buffer)} pacotes não confirmados")
        
        return success

    def do_key_exchange_as_client(self) -> bool:
        print("[KEY_EXCHANGE] Iniciando troca de chaves (cliente)...")
        
        if not self.connected:
            print("[KEY_EXCHANGE] Não conectado, impossível trocar chaves")
            return False
        
        try:
            # Gerar parâmetros Diffie-Hellman
            g, p, private_key = self.crypto.generate_dh_params()
            self.dh_generator = g
            self.dh_prime = p
            self.dh_private_key = private_key
            
            # Calcular chave pública
            public_key = self.crypto.compute_dh_public(g, p, private_key)
            
            # Preparar dados para envio - usar 'Q' para unsigned long long (8 bytes)
            key_data = struct.pack('!QQQ', g, p, public_key)
            
            # Enviar pacote de troca de chaves
            key_packet = TRUPacket(
                seq_num=self.next_seq,
                ack_num=0,
                packet_type=PacketType.KEY_EXCHANGE,
                window=self.window_size,
                checksum=0,
                timestamp=time.time(),
                iv=b'',
                data=key_data
            )
            key_packet.checksum = key_packet.calculate_checksum()
            self.next_seq += 1
            
            print(f"[KEY_EXCHANGE] Enviando parâmetros DH: g={g}, p={p}, public_key={public_key}")
            print(f"[KEY_EXCHANGE] Dados serializados: {len(key_data)} bytes")
            self._send_raw(key_packet, self.peer_addr)
            
            # Aguardar resposta do servidor
            print("[KEY_EXCHANGE] Aguardando resposta do servidor...")
            if self.key_exchange_event.wait(timeout=10.0):
                print("[KEY_EXCHANGE] Troca de chaves completada com sucesso")
                return True
            else:
                print("[KEY_EXCHANGE] Timeout na troca de chaves")
                return False
                
        except Exception as e:
            print(f"[KEY_EXCHANGE] Erro durante troca de chaves: {e}")
            import traceback
            traceback.print_exc()
            return False

    def do_key_exchange_as_server(self) -> bool:
        print("[KEY_EXCHANGE] Aguardando troca de chaves do cliente...")
        
        if not self.connected:
            print("[KEY_EXCHANGE] Não conectado, impossível trocar chaves")
            return False
        
        self.key_exchange_event.clear()
        
        if self.key_exchange_event.wait(timeout=30.0):
            print("[KEY_EXCHANGE] Troca de chaves completada com sucesso")
            return True
        else:
            print("[KEY_EXCHANGE] Timeout aguardando troca de chaves")
            return False

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
                self._deliver_data()
                time.sleep(0.01)
        
        return data

    def close(self):
        print("[CLOSE] Fechando conexão...")
        
        if self.connected and self.peer_addr:
            # Enviar FIN
            fin_packet = TRUPacket(
                seq_num=self.next_seq,
                ack_num=0,
                packet_type=PacketType.FIN,
                window=self.window_size,
                checksum=0,
                timestamp=time.time(),
                iv=b'',
                data=b''
            )
            fin_packet.checksum = fin_packet.calculate_checksum()
            self.next_seq += 1
            
            self._send_raw(fin_packet, self.peer_addr)
            
            # Esperar FIN-ACK
            try:
                self.sock.settimeout(2.0)
                data, _ = self.sock.recvfrom(1024)
                packet = TRUPacket.deserialize(data)
                
                if packet.packet_type == PacketType.FIN_ACK:
                    print("[CLOSE] Conexão fechada corretamente")
            except socket.timeout:
                print("[CLOSE] Timeout ao fechar conexão")
        
        # Parar threads
        self.running = False
        
        if self.receiver_thread:
            self.receiver_thread.join(timeout=1.0)
        if self.timer_thread:
            self.timer_thread.join(timeout=1.0)
        
        self.sock.close()
        self.connected = False
        print("[CLOSE] Conexão fechada")

    def get_rtt_stats(self) -> dict:
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

    def _handle_key_exchange(self, packet: TRUPacket, addr: Tuple[str, int]):
        print(f"[KEY_EXCHANGE] Recebido pedido de troca de chaves do cliente")
        
        try:
            if len(packet.data) < 24: 
                print(f"[KEY_EXCHANGE] Dados insuficientes para troca de chaves")
                return
                
            g, p, client_public = struct.unpack('!QQQ', packet.data[:24])
            print(f"[KEY_EXCHANGE] Parâmetros recebidos: g={g}, p={p}, client_public={client_public}")
            
            server_private = random.randint(1, p-2)
            
            server_public = self.crypto.compute_dh_public(g, p, server_private)
            
            shared_secret = self.crypto.compute_dh_shared(client_public, server_private, p)
            
            encryption_key, salt = self.crypto.derive_key(shared_secret)
            self.encryption_key = encryption_key
            self.encryption_enabled = True
            
            self.iv = os.urandom(16)
            
            print(f"[KEY_EXCHANGE] Chave derivada com sucesso (tamanho: {len(encryption_key)} bytes)")
            print(f"[KEY_EXCHANGE] IV gerado: {self.iv.hex()[:16]}...")
            
            if not self.crypto.test_encryption(encryption_key):
                print(f"[KEY_EXCHANGE] Teste de criptografia falhou")
                return
            
            response_data = struct.pack('!Q', server_public) + struct.pack('!H', len(self.iv)) + self.iv
            
            key_response = TRUPacket(
                seq_num=self.next_seq,
                ack_num=packet.seq_num + 1,
                packet_type=PacketType.KEY_RESPONSE,
                window=self.window_size,
                checksum=0,
                timestamp=time.time(),
                iv=b'',
                data=response_data
            )
            key_response.checksum = key_response.calculate_checksum()
            self.next_seq += 1
            
            print(f"[KEY_EXCHANGE] Enviando resposta de troca de chaves")
            self._send_raw(key_response, addr)
            
        except Exception as e:
            print(f"[KEY_EXCHANGE] Erro durante troca de chaves: {e}")
            import traceback
            traceback.print_exc()

    def _handle_key_response(self, packet: TRUPacket):
        print(f"[KEY_RESPONSE] Recebida resposta de troca de chaves do servidor")
        
        try:
            if len(packet.data) < 10: 
                print(f"[KEY_RESPONSE] Dados insuficientes")
                return
                
            server_public = struct.unpack('!Q', packet.data[:8])[0]
            
            iv_length = struct.unpack('!H', packet.data[8:10])[0]
            
            if len(packet.data) >= 10 + iv_length:
                self.iv = packet.data[10:10+iv_length]
            else:
                print(f"[KEY_RESPONSE] IV incompleto ou ausente")
                return
            
            if not all([self.dh_private_key, self.dh_prime, self.dh_generator]):
                print(f"[KEY_RESPONSE] Parâmetros DH não inicializados")
                return
                
            shared_secret = self.crypto.compute_dh_shared(server_public, self.dh_private_key, self.dh_prime)
            
            encryption_key, salt = self.crypto.derive_key(shared_secret)
            self.encryption_key = encryption_key
            self.encryption_enabled = True
            
            print(f"[KEY_RESPONSE] Chave derivada com sucesso (tamanho: {len(encryption_key)} bytes)")
            print(f"[KEY_RESPONSE] IV recebido: {self.iv.hex()[:16]}...")
            
            if self.crypto.test_encryption(encryption_key):
                print(f"[KEY_RESPONSE] Criptografia testada com sucesso!")
                self.key_exchange_event.set()
            else:
                print(f"[KEY_RESPONSE] Teste de criptografia falhou")
                
        except Exception as e:
            print(f"[KEY_RESPONSE] Erro ao processar resposta: {e}")
            import traceback
            traceback.print_exc()