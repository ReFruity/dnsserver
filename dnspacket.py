import struct

class DnsPacket:
    def __init__(self, bytes):
        self.bytes = bytes
        self.id = bytes[0:2]
        self.parseflags(bytes[2:4])
        # number of queries
        self.qdcount = parseshort(bytes[4:6])
        # number of answers
        self.ancount = parseshort(bytes[6:8])
        # number of name server resource records in the authority section
        self.nscount = parseshort(bytes[8:10])
        # number of records in the additional section
        self.arcount = parseshort(bytes[10:12])
        self.questions = [dict() for _ in range(self.qdcount)]
        self.answers = [dict() for _ in range(self.ancount + self.nscount + self.arcount)]
        pointer = 12

        # question and answer sections
        for i in range(0, self.qdcount):
            name, nameraw = parsename(bytes, pointer)
            length = len(nameraw)
            self.questions[i]["QName"] = name
            pointer += length

            self.questions[i]["QType"] = bytes[pointer:pointer+2]

            self.questions[i]["QClass"] = bytes[pointer+2:pointer+4]
            pointer += 4

        self.buildquestions()

        for i in range(0, self.ancount + self.nscount + self.arcount):
            name, nameraw = parsename(bytes, pointer)
            length = len(nameraw)

            self.answers[i]["NameRaw"] = nameraw
            self.answers[i]["Name"] = name
            # TODO: cname
            pointer += length

            self.answers[i]["Type"] = bytes[pointer:pointer+2]

            self.answers[i]["Class"] = bytes[pointer+2:pointer+4]

            self.answers[i]["TTLRaw"] = bytes[pointer+4:pointer+8]
            self.answers[i]["TTL"] = parseint(bytes[pointer+4:pointer+8])

            RDLengthRaw = bytes[pointer+8:pointer+10]
            self.answers[i]["RDLengthRaw"] = RDLengthRaw
            pointer += 10

            RDLength = parseshort(RDLengthRaw)
            self.answers[i]["RData"] = bytes[pointer:pointer+RDLength]
            pointer += RDLength

        self.buildanswers()

        assert(pointer == len(bytes))

    def parseflags(self, flags):
        self.flags = flags
        # query; 0 for a question, 1 for an answer
        self.qr = (int(flags[0]) & 0b10000000) >> 7
        # request/operation type, 0 for a standard query
        self.opcode = (int(flags[0]) & 0b01111000) >> 3
        # Authoritative Answer
        self.aa = (int(flags[0]) & 0b00000100) >> 2
        # truncated
        self.tc = (int(flags[0]) & 0b00000010) >> 1
        # recursion desired
        self.rd = (int(flags[0]) & 0b00000001)
        # recursion available
        self.ra = (int(flags[1]) & 0b10000000) >> 7
        # reserved stuff
        self.res = (int(flags[1]) & 0b01110000) >> 4
        # response type, 0 for no error, 1 format error, etc
        self.rcode = (int(flags[1]) & 0b00001111)

    def buildflags(self):
        flags = [0, 0]
        flags[0] = self.qr << 7 | self.opcode << 3 | self.aa << 2 | self.tc << 1 | self.rd
        flags[1] = self.ra << 7 | self.res << 4 | self.rcode
        self.flags = bytes(flags)

    def buildquestions(self):
        for i in self.questions:
            i["Raw"] = toname(i["QName"])
            i["Raw"] += i["QType"]
            i["Raw"] += i["QClass"]

    def buildanswers(self):
        for i in self.answers:
            # questionable behavior
            i["TTLRaw"] = itobytes(i["TTL"])

            i["Raw"] =  i["NameRaw"]
            i["Raw"] += i["Type"]
            i["Raw"] += i["Class"]
            i["Raw"] += i["TTLRaw"]
            i["Raw"] += i["RDLengthRaw"]
            i["Raw"] += i["RData"]

    def build(self):
        self.buildflags()
        self.buildquestions()
        self.buildanswers()
        debug = stobytes(self.qdcount)
        self.bytes = self.id + self.flags + \
                     stobytes(self.qdcount) + stobytes(self.ancount) + \
                     stobytes(self.nscount) + stobytes(self.arcount)
        for i in self.questions:
            self.bytes += i["Raw"]
        for i in self.answers:
            self.bytes += i["Raw"]

# short is 2-byte integer here
def stobytes(short):
    return struct.pack(">H", short)

# integer is 4-byte integer here
def itobytes(integer):
    # additional safety for floats, kind of :/
    integer = int(integer)
    return struct.pack(">I", integer)

# hword is half word (2 bytes)
def parseptr(hword):
    return ((hword[0] & 0b00111111) << 8) | hword[1]

def ispointer(hword):
    mask = 0b11000000
    return hword[0] & mask == mask

def parsename(bytestring, startpos):
    pos = startpos
    char = bytestring[pos]
    name = ""
    raw = b""
    while char != 0:
        hword = bytestring[pos:pos+2]
        if ispointer(hword):
            name += parsename(bytestring, parseptr(hword))[0]
            raw += hword
            return (name, raw)
        raw += bytes([char])
        pos += 1
        name += bytestring[pos:pos+char].decode() + "."
        raw += bytestring[pos:pos+char]
        pos += char
        char = bytestring[pos]
    raw += bytes([0])
    return (name[:-1], raw)

def toname(hostname):
    name = b""
    index = 0
    token = b""
    if hostname and hostname[-1] != ".":
        hostname += "."
    for c in hostname:
        if c == ".":
            name += bytes([index]) + token
            token = b""
            index = 0
            continue
        else:
            token += c.encode()
            index += 1
    name += b"\x00"
    return name

# short is 2 bytes
def parseshort(bytestring):
    return struct.unpack(">H", bytestring)[0]

# int is 4 bytes
def parseint(bytestring):
    return struct.unpack(">I", bytestring)[0]

def main():
    pa = DnsPacket(anspacket)
    pmu = DnsPacket(multianspacket)
    pns = DnsPacket(nslookuppacket)
    pdig = DnsPacket(digpacket)

    pa.build()
    pmu.build()
    pns.build()
    pdig.build()

    assert pa.bytes == anspacket
    assert pmu.bytes == multianspacket
    assert pns.bytes == nslookuppacket
    assert pdig.bytes == digpacket

    for p in testpackets:
        currentp = DnsPacket(p)
        currentp.build()
        assert currentp.bytes == p

digpacket = b'I\xeb\x01 \x00\x01\x00\x00\x00\x00\x00\x01\x02e1\x02ru\x00\x00' \
            b'\x01\x00\x01\x00\x00)\x10\x00\x00\x00\x00\x00\x00\x00'
nslookuppacket =  b'\x00\x02\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02e1\x02ru' \
                  b'\x00\x00\x01\x00\x01'
# convex.ru
anspacket = bytes.fromhex(
            "42378180000100010000000106636f6e7665780272750000010001c0"
            "0c0001000100000df30004c340c1aa0000290200000000000000"
          # "7fc18180000100010000000106636f6e7665780272750000010001c0"
          # "0c000100010000086e0004c340c1aa0000290200000000000000"
)
# www.convex.ru
anspacket = bytes.fromhex(
            "aa7181a000010002000000000377777706636f6e76657802727500000"
            "10001c00c0005000100000659000b06636f6e76657802727500c02b00"
            "010001000006590004c340c1aa")
multianspacket = bytes.fromhex(
            "0b54818000010010000000001273"
            "61666562726f7773696e672d636163686506676f6f676c6503636f6d"
            "0000010001c00c000500010009002b00170c7361666562726f777369"
            "6e67056361636865016cc01fc03b00010001000000e30004c340d539"
            "c03b00010001000000e30004c340d526c03b00010001000000e30004"
            "c340d51dc03b00010001000000e30004c340d52cc03b000100010000"
            "00e30004c340d531c03b00010001000000e30004c340d53bc03b0001"
            "0001000000e30004c340d51bc03b00010001000000e30004c340d517"
            "c03b00010001000000e30004c340d52dc03b00010001000000e30004"
            "c340d522c03b00010001000000e30004c340d535c03b000100010000"
            "00e30004c340d50fc03b00010001000000e30004c340d513c03b0001"
            "0001000000e30004c340d52ac03b00010001000000e30004c340d51e"
)

testpackets = [
    "215a0120000100000000000106636f6e76657802727500000100010000291000000000000000",
    "215a8180000100010000000106636f6e7665780272750000010001c00c00010001000004fc0004c340c1aa0000290200000000000000",
    "f0200120000100000000000106636f6e76657802727500000100010000291000000000000000",
    "f02081a0000100010000000006636f6e7665780272750000010001c00c00010001000006530004c340c1aa",
]
testpackets = [bytes.fromhex(x) for x in testpackets]

if __name__ == "__main__":
    main()