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
    KEY_EXCHANGE = 7
    KEY_RESPONSE = 8

@dataclass
class TRUPacket:
    seq_num: int = 0
    ack_num: int = 0
    packet_type: int = 0
    window: int = 1024
    checksum: int = 0
    timestamp: float = 0.0
    iv: bytes = b''
    data: bytes = b''

    HEADER_SIZE = 23 + 16   # seq(4) + ack(4) + type(1) + window(2) + checksum(4) + timestamp(8)

    def serialize(self) -> bytes:
        timestamp_micro = int(self.timestamp * 1000000)
        
        iv_bytes = self.iv if self.iv else bytes(16)
        if len(iv_bytes) < 16:
            iv_bytes = iv_bytes + bytes(16 - len(iv_bytes))
        elif len(iv_bytes) > 16:
            iv_bytes = iv_bytes[:16]
        
        header = struct.pack('!IIBHIQ',
                        self.seq_num,
                        self.ack_num,
                        self.packet_type,
                        self.window,
                        self.checksum,
                        timestamp_micro)
        return header + iv_bytes + self.data

        
    @staticmethod
    def deserialize(data: bytes) -> 'TRUPacket':
        try:
            if len(data) < 39:
                raise ValueError(f"Pacote muito pequeno: {len(data)} bytes (mínimo 39)")
            
            # Desempacotar cabeçalho: seq(4), ack(4), type(1), window(2), checksum(4), timestamp(8)
            header = data[:23]
            (seq_num, ack_num, packet_type, window, checksum, timestamp_micro) = struct.unpack('!IIBHIQ', header)
            
            timestamp = timestamp_micro / 1000000.0
            
            # IV (16 bytes)
            iv = data[23:39]
            
            # Dados do pacote
            packet_data = data[39:]
            
            packet = TRUPacket(seq_num, ack_num, packet_type, window, checksum, timestamp, iv, packet_data)
            
            return packet
        except struct.error as e:
            raise ValueError(f"Erro de struct ao deserializar pacote: {e}")

    
    def calculate_checksum(self) -> int:
        old_checksum = self.checksum
        self.checksum = 0
        
        data = self.serialize()
        
        if len(data) % 2 == 1:
            data += b'\x00'
            
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + (data[i+1])
            s += w
            while (s >> 16):
                s = (s & 0xFFFF) + (s >> 16)
                
        self.checksum = old_checksum
        return ~s & 0xFFFF

    def is_valid(self) -> bool:
        return self.checksum == self.calculate_checksum()