import struct

class DnsPacket:

    def __init__(self, packet):
        self.packet = packet
        self.id = packet[0:2]
        flags = packet[2:4]
        self.qr = int(flags[0]) & binary("10000000")
        self.opcode = int(flags[0]) & binary("01111000")
        self.qdcount = parseshort(packet[4:6])
        self.ancount = parseshort(packet[6:8])
        self.nscount = parseshort(packet[8:10])
        self.arcount = parseshort(packet[10:12])
        if self.question = (packet[12:])
        print(self.QR)

class Bits:
    def __init__(self, bytestring):
        pass

def binary(string):
    return int(string, 2)

def parseshort(bytestring):
    return struct.unpack(">H", bytestring)[0]

def main():
    packet  = b'I\xeb\x01 \x00\x01\x00\x00\x00\x00\x00\x01\x02e1\x02ru\x00\x00' \
              b'\x01\x00\x01\x00\x00)\x10\x00\x00\x00\x00\x00\x00\x00'
    packet2 = b'\xea\x02\x01 \x00\x01\x00\x00\x00\x00\x00\x01\x02e1\x02ru\x00' \
              b'\x00\x01\x00\x01\x00\x00)\x10\x00\x00\x00\x00\x00\x00\x00'
    packet3 = b'\n\xa7\x01 \x00\x01\x00\x00\x00\x00\x00\x01\x02e1\x02ru\x00' \
              b'\x00\x01\x00\x01\x00\x00)\x10\x00\x00\x00\x00\x00\x00\x00'
    packet4 = b'C\xd5\x01 \x00\x01\x00\x00\x00\x00\x00\x01\x02e1\x02ru\x00' \
              b'\x00\x01\x00\x01\x00\x00)\x10\x00\x00\x00\x00\x00\x00\x00'
    nspacket= b'\x00\x02\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02e1\x02ru' \
              b'\x00\x00\x01\x00\x01'
    p = DnsPacket(packet3)
    p2 = DnsPacket(nspacket)
    print(p.QR)

if __name__ == "__main__":
    main()