import socket


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


class DNSMessage:
    def __init__(self, header: DNSHeader):
        self._header = header 

    def payload(self) -> bytes:
        return self._header.payload()


def main():

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
    
            header = DNSHeader(bytearray(12))
            header.id = 0x04D2 # 1234
            header.qr = 0x01

            message = DNSMessage(header)
            response = message.payload()
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
