import socket
import dnspacket

def main():
    debug = True

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 53))
    print("Dns server bound to 127.0.0.1, port 53")

    while True:
        packet = s.recv(1024)
        p = dnspacket.DnsPacket(packet)
        if debug: print(p.QR)

if __name__ == "__main__":
    main()