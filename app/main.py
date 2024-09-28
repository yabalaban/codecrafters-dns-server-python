import socket

from dataclasses import dataclass
from enum import Enum
from typing import Tuple


def _32bit_get(data: bytearray, offset: int) -> int:
    return (data[offset] << 24) + (data[offset + 1] << 16) + (data[offset + 2] << 8) + data[offset + 3]


def _32bit_set(data: bytearray, offset: int, value: int):
    data[offset] = (value & 0xFF000000) >> 24
    data[offset + 1] = (value & 0x00FF0000) >> 16
    data[offset + 2] = (value & 0x0000FF00) >> 8
    data[offset + 3] = (value & 0x000000FF)


def _16bit_get(data: bytearray, offset: int) -> int:
    return (data[offset] << 8) + data[offset + 1]


def _16bit_set(data: bytearray, offset: int, value: int):
    data[offset] = (value & 0xFF00) >> 8
    data[offset + 1] = value & 0x00FF


def _bit_get(data: bytearray, offset: int, shift: int) -> int:
    return (data[offset] & (0x01 << shift)) >> shift


def _bit_set(data: bytearray, offset: int, shift: int, value: int):
    data[offset] = data[offset] & ~(1 << shift)
    if value:
        data[offset] = data[offset] | (1 << shift)


def _bits_get(data: bytearray, offset: int, mask: int, shift: int) -> int:
    return (data[offset] & mask) >> shift


def _bits_set(data: bytearray, offset: int, mask: int, shift: int, value: int):
    data[offset] = data[offset] & ~mask
    data[offset] = data[offset] | (value << shift)


def _encode_labels(value) -> bytearray:
    arr = bytearray()
    for label in value.split('.'):
        arr.append(len(label))
        arr.extend(bytes(label, encoding='utf-8'))
    arr.append(0x00)
    return arr


def _decode_labels(bytes: bytearray, offset: int) -> Tuple[str, int]:
    s = ''
    while bytes[offset] != 0x00: 
        n = int(bytes[offset])
        offset += 1
        s += bytes[offset: offset + n].decode("utf-8")
        offset += n 
    return (s, offset)


class DNSHeader:
    def __init__(self, payload: bytearray):
        assert(len(payload) == 12)
        self._payload = payload

    def payload(self) -> bytes:
        return bytes(self._payload)

    @property 
    def id(self) -> int:
        return _16bit_get(self._payload, 0)
    
    @id.setter
    def id(self, value: int):
        return _16bit_set(self._payload, 0, value)

    @property 
    def qr(self) -> int:
        return _bit_get(self._payload, 2, 7)
    
    @qr.setter
    def qr(self, value: int):
        _bit_set(self._payload, 2, 7, value)

    @property 
    def opcode(self) -> int:
        return _bits_get(self._payload, 2, 0b01111000, 3)
    
    @opcode.setter
    def opcode(self, value: int):
        _bits_set(self._payload, 2, 0b01111000, 3, value & 0b00001111)

    @property 
    def aa(self) -> int:
        return _bits_get(self._payload, 2, 0b00000100, 2)
    
    @aa.setter
    def aa(self, value: int):
        _bits_set(self._payload, 2, 0b00000100, 2, value & 0b00000001)

    @property 
    def tc(self) -> int:
        return _bits_get(self._payload, 2, 0b00000010, 1)
    
    @tc.setter
    def tc(self, value: int):
        _bits_set(self._payload, 2, 0b00000010, 1, value & 0b00000001)

    @property 
    def rd(self) -> int:
        return _bits_get(self._payload, 2, 0b00000001, 0)
    
    @rd.setter
    def rd(self, value: int):
        _bits_set(self._payload, 2, 0b00000001, 0, value & 0b00000001)

    @property 
    def ra(self) -> int:
        return _bits_get(self._payload, 3, 0b10000000, 7)
    
    @ra.setter
    def ra(self, value: int):
        _bits_set(self._payload, 3, 0b10000000, 7, value & 0b00000001)

    @property 
    def z(self) -> int:
        return _bits_get(self._payload, 3, 0b01110000, 4)
    
    @z.setter
    def z(self, value: int):
        _bits_set(self._payload, 3, 0b01110000, 4, value & 0b00000111)
    
    @property 
    def rcode(self) -> int:
        return _bits_get(self._payload, 3, 0b00001111, 0)
    
    @rcode.setter
    def rcode(self, value: int):
        _bits_set(self._payload, 3, 0b00001111, 0, value & 0b00001111)

    @property 
    def qdcount(self) -> int:
        return _16bit_get(self._payload, 4)
    
    @qdcount.setter
    def qdcount(self, value: int):
        _16bit_set(self._payload, 4, value)

    @property 
    def ancount(self) -> int:
        return _16bit_get(self._payload, 6)
    
    @ancount.setter
    def ancount(self, value: int):
        _16bit_set(self._payload, 6, value)

    @property 
    def nscount(self) -> int:
        return _16bit_get(self._payload, 8)
    
    @nscount.setter
    def nscount(self, value: int):
        _16bit_set(self._payload, 8, value)

    @property 
    def arcount(self) -> int:
        return _16bit_get(self._payload, 10)
    
    @arcount.setter
    def arcount(self, value: int):
        _16bit_set(self._payload, 10, value)


class DNSRRType(Enum):
    # TYPE fields are used in resource records.  Note that these types are a
    # subset of QTYPEs.

    A = 1       # a host address                
    NS = 2      # an authoritative name server
    MD = 3      # a mail destination (Obsolete - use MX)
    MF = 4      # a mail forwarder (Obsolete - use MX)
    CNAME = 5   # the canonical name for an alias
    SOA = 6     # marks the start of a zone of authority
    MB = 7      # a mailbox domain name (EXPERIMENTAL)
    MG = 8      # a mail group member (EXPERIMENTAL)
    MR = 9      # a mail rename domain name (EXPERIMENTAL)
    NULL = 10   # a null RR (EXPERIMENTAL)
    WKS = 11    # a well known service description
    PTR = 12    # a domain name pointer
    HINFO = 13  # host information
    MINFO = 14  # mailbox or mail list information
    MX = 15     # mail exchange
    TXT = 16    # text strings


class DNSRRClass(Enum):
    # CLASS fields appear in resource records.  The following CLASS mnemonics
    # and values are defined:

    IN = 1 # the Internet
    CS = 2 # the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH = 3 # the CHAOS class
    HS = 4 # Hesiod [Dyer 87]


class DNSQuestion:
    def __init__(self, payload: bytearray):
        self._payload = payload 

    def payload(self) -> bytearray:
        return bytearray(self._payload)
    
    @property
    def domain_name(self) -> str:
        return _decode_labels(self._payload, 0)[0]
    
    @domain_name.setter
    def domain_name(self, value: str) -> str:
        self._payload[:-4] = _encode_labels(value)
    
    @property
    def typ(self) -> DNSRRType:
        return DNSRRType(_16bit_get(self._payload, len(self._payload) - 4))
    
    @typ.setter
    def typ(self, ty: DNSRRType):
        _16bit_set(self._payload, len(self._payload) - 4, ty.value)

    @property
    def cls(self) -> DNSRRClass:
        return DNSRRClass(_16bit_get(self._payload, len(self._payload) - 2))
    
    @cls.setter
    def cls(self, cls: DNSRRClass):
        _16bit_set(self._payload, len(self._payload) - 2, cls.value)


class DNSAnswer:
    def __init__(self, payload: bytearray):
        self._payload = payload 
        self._label_len = 0

    def payload(self) -> bytearray:
        return bytearray(self._payload)

    def labels(self) -> bytearray:
        return self._payload[:-4]
    
    @property
    def name(self) -> str:
        return _decode_labels(self._payload, 0)[0]
    
    @name.setter
    def name(self, value: str):
        bytes = _encode_labels(value)
        self._payload[:self._label_len] = bytes
        self._label_len = len(bytes)
    
    @property
    def typ(self) -> DNSRRType:
        return DNSRRType(_16bit_get(self._payload, self._label_len))
    
    @typ.setter
    def typ(self, ty: DNSRRType):
        _16bit_set(self._payload, self._label_len, ty.value)

    @property
    def cls(self) -> DNSRRClass:
        return DNSRRClass(_16bit_get(self._payload, self._label_len + 2))
    
    @cls.setter
    def cls(self, cls: DNSRRClass):
        _16bit_set(self._payload, self._label_len + 2, cls.value)

    @property
    def ttl(self) -> int:
        return _32bit_get(self._payload, self._label_len + 4)
    
    @ttl.setter
    def ttl(self, value: int):
        _32bit_set(self._payload, self._label_len + 4, value)

    @property
    def length(self) -> int:
        return _16bit_get(self._payload, self._label_len + 8)
    
    @length.setter
    def length(self, value: int):
        _16bit_set(self._payload, self._label_len + 8, value)

    @property
    def data(self) -> bytearray:
        return self._payload[self._label_len + 10:]
    
    @data.setter
    def data(self, value: bytearray):
        self.length = len(value)
        self._payload[self._label_len + 10:] = value

@dataclass
class DNSMessage:

    def __init__(self, header: DNSHeader, questions: list[DNSQuestion], answers: list[DNSAnswer]):
        self.header = header
        self.questions = questions
        self.answers = answers
        self.header.qdcount = len(questions)
        self.header.ancount = len(answers)

    def payload(self) -> bytes:
        bytes = bytearray(0)
        bytes.extend(self.header.payload())
        [bytes.extend(q.payload()) for q in self.questions]
        [bytes.extend(a.payload()) for a in self.answers]
        return bytes
        
    @staticmethod 
    def from_bytes(payload: bytes):
        offset = 0
        header = DNSHeader(bytearray(payload[offset:offset + 12]))
        offset += 12
        
        questions = []
        for _ in range(header.qdcount):
            domain_name, offset = _decode_labels(payload, offset)
            offset += 1
            question = DNSQuestion(bytearray(payload[offset: offset + 4]))
            offset += 4
            question.domain_name = domain_name
            questions.append(question)

        answers = []
        for _ in range(header.ancount):
            name, offset = _decode_labels(payload, offset)
            offset += 1
            answer = DNSAnswer(bytearray(payload[offset: offset + 10]))
            offset += 10
            answer.name = name
            data = payload[offset]
            answer.data = bytearray(payload[offset + 1: offset + data + 1])
            offset += data + 1
            answers.append(answer)

        return DNSMessage(header, questions, answers) 

def main():

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
    
            requested = DNSMessage.from_bytes(buf)

            header = DNSHeader(bytearray(12))
            header.id = requested.header.id 
            header.qr = 1
            header.opcode = requested.header.opcode
            header.rd = requested.header.rd
            header.rcode = 0 if requested.header.opcode == 0 else 4 

            questions = [] 
            for q in requested.questions:
                question = DNSQuestion(bytearray(4))
                question.domain_name = q.domain_name
                question.typ = DNSRRType.A
                question.cls = DNSRRClass.IN
                questions.append(question)

            answers = [] 
            for a in requested.answers:
                answer = DNSAnswer(bytearray(10))
                answer.name = a.name
                answer.typ = DNSRRType.A
                answer.cls = DNSRRClass.IN
                answer.ttl = 60
                answer.data = b'\x08\x08\x08\x08'
                answers.append(answer)

            message = DNSMessage(header, questions, answers)
            response = message.payload()
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
