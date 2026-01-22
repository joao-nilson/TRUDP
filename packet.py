import struct
from daraclasses import dataclass
from enum import IntEnum

# 0-4 ao invéz de flags binárias
# um tipo por pacote
class PacketType(IntEnum):
    DATA = 0
    ACK = 1
    SYN = 2
    SYN_ACK = 3
    FIN = 4

@dataclass
class TRUPacket:
    seq_num: int = 0
    ack_num: int = 0
    packet_type: int = 0
    data: bytes = b''

    def serialize(self) -> bytes:
        return struct.pack('!IIB', self.seq_num, self.ack_num, self.packet_type) + self.data
        

    def deserialize(cls, data: bytes) -> 'TRUPacket':
        header = data[:9]
        seq_num, ack_num, packet_type = struct.unpack('!IIB', header)
        packet_data = data[:9] if len(data) > 9 else b''

        return cls(seq_num = seq_num,
                   ack_num = ack_num,
                   packet_type = packet_type,
                   data = packet_data
        )
