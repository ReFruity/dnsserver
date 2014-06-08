import socket
from dnspacket import DnsPacket
from dnscache import Cache
import sys
import argparse

def main():
    debug = False

    argparser = argparse.ArgumentParser(description='Caching DNS Server')
    argparser.add_argument('-f','--forwarder', help='specifies forwarder',
                           required=False, default='8.8.8.8')
    argparser.add_argument('-p','--port', help='specifies port to bind this server too',
                           required=False, default='53')
    args = argparser.parse_args()

    forwarder = args.forwarder
    forwport = 53
    serverport = int(args.port)

    querysocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    querysocket.settimeout(3)

    serversocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    serversocket.bind(("0.0.0.0", serverport))
    serversocket.settimeout(1)
    print("DNS server bound to 0.0.0.0, port", serverport, "\n")

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
                    querysocket.connect((forwarder, forwport))
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