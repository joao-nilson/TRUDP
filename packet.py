import struct
import time
from dataclasses import dataclass
from enum import IntEnum

# 0-4 ao invéz de flags binárias
# um tipo por pacote
class PacketType(IntEnum):
    DATA = 0
    ACK = 1
    SYN = 2
    SYN_ACK = 3
    FIN = 4
    FIN_ACK = 5
    RST = 6

@dataclass
class TRUPacket:
    seq_num: int = 0
    ack_num: int = 0
    packet_type: int = 0
    window: int = 1024
    checksum: int = 0
    timestamp: float = 0.0
    data: bytes = b''

    HEADER_SIZE = 23   #seq(4) + ack(4) + type(1) + window(2) + checksum(4) + timestamp(8)

    def serialize(self) -> bytes:
        header = struct.pack('!IIBHIQ',
                        self.seq_num,
                        self.ack_num,
                        self.packet_type,
                        self.window,
                        self.checksum,
                        int(self.timestamp * 1000000))
        return header + self.data
        
    @classmethod
    def deserialize(cls, data: bytes) -> 'TRUPacket':
        if len(data) < cls.HEADER_SIZE:
            print(f"[DEBUG] Pacote muito pequeno: {len(data)} bytes, esperado {cls.HEADER_SIZE}")
            print(f"[DEBUG] Dados: {data.hex()}")
            raise ValueError("Pacote pequeno demais")

        header = data[:cls.HEADER_SIZE]
        seq_num, ack_num, packet_type, window, checksum, timestamp = struct.unpack('!IIBHIQ', header)
        packet_data = data[cls.HEADER_SIZE:] if len(data) > cls.HEADER_SIZE else b''

        return cls(
            seq_num = seq_num,
            ack_num = ack_num,
            packet_type = packet_type,
            window = window,
            checksum = checksum,
            timestamp = timestamp / 1000000.0,
            data = packet_data
        )
    
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
