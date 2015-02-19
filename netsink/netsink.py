#!/usr/bin/python
# -*- coding: utf8 -*-

import sys
import os
import logging
import argparse
import socket
import threading

log = logging.getLogger(__name__)

# random ip within 10.0.0.0/8
def randip():
    return socket.inet_ntoa("\x0a"+os.urandom(3))

def bin2mac(x):
    return ":".join("%02x" % ord(i) for i in x)

def dns_serv(args):
    from scapy.all import DNS, DNSRR, DNSQR

    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udps.bind((args.bind, 53))
    
    while 1:
        data, addr = udps.recvfrom(1024)

        p = DNS(data)
        rp = DNS(id=p.id, qr=1, qdcount=p.qdcount, ancount=1, rcode=0)
        rp.qd = p[DNSQR]

        if p.opcode == 0:
            if p.qd[0].qname == "dns.msftncsi.com":
                answer_ip = "131.107.255.255"
            else:
                answer_ip = randip()
            rp.an = DNSRR(rrname=p.qd[0].qname, ttl=60, rdlen=4, rdata=answer_ip)
            log.debug("Responding to {0} with {1}.".format(p.qd[0].qname, answer_ip))
        else:
            rp.ancount = 0
            rp.rcode = 2
            log.warn("Query opcode {0} for {1}, answering servfail.".format(p.opcode, p.qd[0].qname))

        udps.sendto(rp.build(), addr)

def open_port(addr, port, proto="tcp"):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if proto == "udp" else socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((addr, port))
        if proto != "udp": s.listen(5)
        return s
    except:
        import traceback
        traceback.print_exc()

    return None

def port_sink(args):
    import select
    import struct

    BUFSIZ = 1024
    SO_ORIGINAL_DST = 80

    listener = open_port(args.bind, 1)
    listener_fd = listener.fileno()

    listener_udp = open_port(args.bind, 1, proto="udp")
    listener_udp_fd = listener_udp.fileno()

    fdset = set([listener_fd, listener_udp_fd])
    conns = {}

    def closesock(fd, sock):
        try: sock.close()
        except: pass
        fdset.remove(fd)
        conns.pop(fd, None)

    while True:
        rfds, wfds, efds = select.select(list(fdset), [], [], 1.0)

        for fd in rfds:
            if fd == listener_fd:
                sock, addr = listener.accept()
                fdset.add(sock.fileno())

                try:
                    odst = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
                    dport, dip = struct.unpack("!2xH4s8x", odst)
                    dip = socket.inet_ntoa(dip)
                except Exception as e:
                    if e.args[0] == 92: # direct connection, doesnt have ODST
                        dip, dport = sock.getsockname()
                    else:
                        raise

                log.debug("Port sink got connection from %s to %s", str(addr), str((dip, dport)))
                conns[sock.fileno()] = (sock, dip, dport)

            elif fd == listener_udp_fd:
                try: data, addr = listener_udp.recvfrom(BUFSIZ)
                except Exception as e:
                    log.debug("Exception on UDP sock:", str(e))
                else:
                    sip, sport = addr
                    log.debug("RECV %s:%u -> unknown_udp: %s", sip, sport, repr(data))

            elif fd in conns:
                sock, dip, dport = conns[fd]
                sip, sport = sock.getpeername()

                try: data = sock.recv(BUFSIZ)
                except:
                    closesock(fd, sock)
                else:
                    log.debug("RECV %s:%u -> %s:%u: %s", sip, sport, dip, dport, repr(data))
                    if not data:
                        closesock(fd, sock)
                    elif "/ncsi.txt HTTP/1." in data:
                        sock.sendall("""HTTP/1.1 200 OK\r
Content-Length: 14\r
Content-Type: text/plain
Cache-Control: max-age=30, must-revalidate\r
\r
Microsoft NCSI""")
                        closesock(fd, sock)                        
                    elif "HTTP/1." in data:
                        sock.sendall("HTTP/1.0 200 OK\r\n\r\nOK")
                        closesock(fd, sock)

def launchthread(fn, *args):
    t = threading.Thread(target=fn, args=args)
    t.daemon = True
    t.start()
    return t

def main():
    import argparse
    import Queue

    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser(description='Network sink, DNS, fake services in a tiny sweet package.')
    parser.add_argument("--bind", help="IP address to bind for DNS and services.", default="192.168.56.1")
    args = parser.parse_args()

    dns_thread = launchthread(dns_serv, args)

    port_sink(args)
    return 0

if __name__ == '__main__':
    try: sys.exit(main())
    except (IOError, KeyboardInterrupt): pass
