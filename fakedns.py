#!/usr/bin/env python

import sys
import socket

from scapy.all import DNS, DNSRR, DNSQR

ANSWER_WITH = "192.168.56.1"
BIND_TO = ANSWER_WITH

def resolve_or_fake(name):
    try: r = socket.gethostbyname(name)
    except socket.gaierror: return ANSWER_WITH
    return r or ANSWER_WITH

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "none"
    if not mode in ["fakenx", "fake"]:
        print >>sys.stderr, 'Please supply argv[1] in ["fakenx", "fake"]'
        return 1

    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.bind((BIND_TO,53))
    
    while 1:
        data, addr = udps.recvfrom(1024)

        p = DNS(data)

        rp = DNS(id=p.id, qr=1, qdcount=p.qdcount)
        rp.qd = p[DNSQR]

        if p.opcode == 0:
            rp.ancount = 1
            rp.rcode = 0
            answer_ip = ANSWER_WITH
            if mode == "fakenx": answer_ip = resolve_or_fake(p.qd[0].qname)
            rp.an = DNSRR(rrname=p.qd[0].qname, ttl=60, rdlen=4, rdata=answer_ip)
            print " - Responding to {0} with {1}.".format(p.qd[0].qname, answer_ip)
        else:
            rp.ancount = 0
            rp.rcode = 2
            print " ! Query opcode {0}, answering servfail.".format(p.opcode)

        udps.sendto(rp.build(), addr)

if __name__ == "__main__":
    try: sys.exit(main())
    except KeyboardInterrupt: pass
