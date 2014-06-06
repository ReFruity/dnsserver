import socket
from dnspacket import DnsPacket
from dnscache import Cache
import sys

def main():
    debug = False
    forwarder = "8.8.8.8"
    port = 53

    sys.argv.pop(0)
    if sys.argv:
        forwarder = sys.argv.pop(0)

    querysocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    querysocket.settimeout(3)

    serversocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    serversocket.bind(("0.0.0.0", 53))
    serversocket.settimeout(1)
    print("DNS server bound to 127.0.0.1, port 53\n")

    cache = Cache("cache.txt")
    cache.read()

    try:
        while True:
            try:
                query, fromaddr = serversocket.recvfrom(1024)
                qpack = DnsPacket(query)
                if debug: print(query)

                print("Query from:", fromaddr)
                print("QName:", qpack.questions[0]["QName"])

                anspack = cache.get(qpack.questions[0]["QName"])
                answer = b""

                if anspack != None:
                    print("Found answer in cache, sending...\n")
                    anspack.id = qpack.id
                    anspack.build()
                    answer = anspack.bytes
                else:
                    print("No answer in cache, asking forwarder...\n")
                    querysocket.connect((forwarder, port))
                    querysocket.send(query)
                    answer = querysocket.recv(1024)
                    anspack = DnsPacket(answer)
                    cache.addentry(anspack)

                serversocket.sendto(answer, fromaddr)
            except socket.error:
                pass
            except Exception as e:
                print(e)
    except KeyboardInterrupt:
        pass
    finally:
        cache.write()
        input("Press enter to exit...")

if __name__ == "__main__":
    main()