import time
import pickle
from dnspacket import DnsPacket, anspacket, multianspacket

class Cache:
    contents = dict()

    def __init__(self, filename):
        self.filename = filename
        self.lastupdated = time.time()
        open(self.filename, "a").close()

    def read(self):
        try:
            c = open(self.filename, "rb")
            self.contents = pickle.load(c)
        except EOFError as e:
            print("Cache file was corrupt:", e)
            print("Assuming cache is empty\n")

    def write(self):
        with open(self.filename, "wb") as c:
            pickle.dump(self.contents, c)

    def update(self):
        keys = list(self.contents.keys())
        for i in keys:
            for j in self.contents[i].answers:
                TTL = j["TTL"]
                # questionable behavior: skipping not-to-cache entries
                if not TTL: continue
                remtime = (self.lastupdated + TTL) - time.time()
                if remtime <= 0:
                    del self.contents[i]
                    break
                else:
                    j["TTL"] = remtime
        self.lastupdated = time.time()

    def addentry(self, packet):
        self.contents[packet.questions[0]["QName"]] = packet
        self.update()

    def get(self, name):
        self.update()
        return self.contents.get(name, None)


def main():
    testcache = Cache("testfile.txt")
    testcache.addentry(DnsPacket(anspacket))
    testcache.addentry(DnsPacket(multianspacket))
    # testcache.write()
    # testcache.read()
    debug1 = testcache.get("e1.ru")
    debug2 = testcache.get("convex.ru")
    pass

if __name__ == "__main__":
    main()