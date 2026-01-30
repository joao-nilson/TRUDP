import struct
import time
from dataclasses import dataclass
from enum import IntEnum

class PacketType(IntEnum):
    SYN = 1
    SYN_ACK = 2
    ACK = 3
    DATA = 4
    FIN = 5
    FIN_ACK = 6

@dataclass
class TRUPacket:
    seq_num: int = 0
    ack_num: int = 0
    packet_type: int = 0
    window: int = 1024
    checksum: int = 0
    timestamp: float = 0.0
    data: bytes = b''

    HEADER_SIZE = 23   # seq(4) + ack(4) + type(1) + window(2) + checksum(4) + timestamp(8)

    def serialize(self) -> bytes:
        timestamp_micro = int(self.timestamp * 1000000)
        
        header = struct.pack('!IIBHIQ',
                        self.seq_num,
                        self.ack_num,
                        self.packet_type,
                        self.window,
                        self.checksum,
                        timestamp_micro)
        return header + self.data
        
    @staticmethod
    def deserialize(data: bytes) -> 'TRUPacket':
        try:
            if len(data) < 23:
                raise ValueError(f"Pacote muito pequeno: {len(data)} bytes (mínimo 23)")
            
            # Desempacotar cabeçalho: seq(4), ack(4), type(1), window(2), checksum(4), timestamp(8)
            # Formato: '!IIBHIQ' -> 4+4+1+2+4+8 = 23 bytes
            header = data[:23]
            (seq_num, ack_num, packet_type, window, checksum, timestamp_micro) = struct.unpack('!IIBHIQ', header)
            
            # Converter timestamp de microssegundos para segundos
            timestamp = timestamp_micro / 1000000.0
            
            # Dados do pacote (tudo após o cabeçalho)
            packet_data = data[23:]
            
            packet = TRUPacket(seq_num, ack_num, packet_type, window, checksum, timestamp, packet_data)
            
            return packet
        except struct.error as e:
            raise ValueError(f"Erro de struct ao deserializar pacote: {e}")
    
    def calculate_checksum(self) -> int:
        # Salvar checksum atual e zerar para cálculo
        old_checksum = self.checksum
        self.checksum = 0
        
        # Serializar dados
        data = self.serialize()
        
        # Garantir que o comprimento seja par
        if len(data) % 2 == 1:
            data += b'\x00'
            
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + (data[i+1])
            s += w
            # Adicionar overflow
            while (s >> 16):
                s = (s & 0xFFFF) + (s >> 16)
                
        # Restaurar checksum
        self.checksum = old_checksum
        # Retornar complemento de 1
        return ~s & 0xFFFF

    def is_valid(self) -> bool:
        return self.checksum == self.calculate_checksum()