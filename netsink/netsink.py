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
            answer_ip = randip()
            rp.an = DNSRR(rrname=p.qd[0].qname, ttl=60, rdlen=4, rdata=answer_ip)
            log.debug("Responding to {0} with {1}.".format(p.qd[0].qname, answer_ip))
        else:
            rp.ancount = 0
            rp.rcode = 2
            log.warn("Query opcode {0} for {1}, answering servfail.".format(p.opcode, p.qd[0].qname))

        udps.sendto(rp.build(), addr)

def dhcp_serv(args):
    import random
    from scapy.all import DHCP, BOOTP, DHCPTypes

    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # SO_BINDTODEVICE = 25
    udps.setsockopt(socket.SOL_SOCKET, 25, "vboxnet0");
    udps.bind(("255.255.255.255", 67))

    # TODO: make configurable
    pool = set("192.168.56.%u" % i for i in range(10, 250))
    leases = {}
    offers = {}
    taken = set()
    
    while 1:
        data, addr = udps.recvfrom(1024)

        p = BOOTP(data)
        mac = bin2mac(p.chaddr[:6])

        if not p.haslayer(DHCP):
            log.critical("Got BOOTP without DHCP layer, what's up with that?")
            continue

        pdhcp = p.getlayer(DHCP)
        popts = dict(i for i in pdhcp.options if type(i) == tuple)
        mtype = DHCPTypes.get(popts.get("message-type", None), "unknown")
        reqaddr = popts.get("requested_addr", None)
        hostname = popts.get("hostname", "unknown")

        log.debug("DHCP %s from %s (hostname %s), ciaddr %s reqaddr %s", mtype, mac, hostname, p.ciaddr, reqaddr)

        if mtype == "discover":
            offerip = random.choice(list(pool-taken))

            options = [("message-type", "offer"), ("lease_time", 60), ("renewal_time", 60),
                ("subnet_mask", "255.255.255.0"), ("broadcast_address", "192.168.56.255"), ("router", "192.168.56.1"),
                ("name_server", "192.168.56.1"), ("domain", "cuckoo"), ("hostname", hostname), 255]

            rp = BOOTP(op=2, xid=p.xid, yiaddr=offerip, chaddr=p.chaddr) / DHCP(options=options)

            offers[(mac, offerip)] = rp
            log.debug("Offering %s to %s", offerip, mac)

        elif mtype == "request":
            rp = offers.get((mac, reqaddr), None)
            if rp is None:
                rp = offers.get((mac, p.ciaddr), None)
                if rp is None:
                    log.warn("Request for an IP we did not offer, ignoring.")
                    continue

            rp.getlayer(DHCP).options = [("message-type", "ack"),] + rp.getlayer(DHCP).options[1:]

            leases[mac] = {"addr": reqaddr, "hostname": hostname}
            log.debug("Ack for %s to %s", offerip, mac)

        else:
            log.warn("Unknown message type: %s", mtype)
            continue

        if addr[0] == "0.0.0.0":
            addr = ("255.255.255.255", addr[1])

        udps.sendto(rp.build(), addr)


def open_port(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("192.168.56.1", port))
        s.listen(5)
        return s
    except:
        pass

    return None

def port_sink(portqueue, notifyfd, donefd):
    import select
    import time

    BUFSIZ = 16384
    open_ports = []
    listeners = {}
    conns = {}
    fdset = set([notifyfd,])

    def closesock(fd, sock):
        try: sock.close()
        except: pass

        fdset.remove(fd)
        conns.pop(fd, None)
        listeners.pop(fd, None)


    while True:
        rfds, wfds, efds = select.select(list(fdset), [], [], 1.0)
        if notifyfd in rfds:
            os.read(notifyfd, 1)

            while not portqueue.empty():
                port = portqueue.get()
                sock = open_port(port)
                if not sock:
                    log.debug("Port sink failed to open port %u", port)
                    continue

                log.debug("Port sink opened port %u", port)

                now = time.time()
                open_ports.append((now, port, sock.fileno(), sock))
                listeners[sock.fileno()] = sock
                fdset.add(sock.fileno())

            rfds.remove(notifyfd)
            os.write(donefd, "B")

        for fd in rfds:
            # listeners
            if fd in listeners:
                sock = listeners[fd]
                newsock, addr = sock.accept()
                log.debug("Port sink got connection from %s", str(addr))
                conns[newsock.fileno()] = newsock
                fdset.add(newsock.fileno())

            elif fd in conns:
                sock = conns[fd]
                try: data = sock.recv(BUFSIZ)
                except:
                    closesock(fd, sock)
                else:
                    log.debug("RECV: %s", repr(data))
                    if not data:
                        closesock(fd, sock)

        # close any older listeners so we don't keep around thousands of them
        now = time.time()
        for tc, port, fd, sock in open_ports:
            if now - tc >= 5.0:
                # older than 5 seconds, close it
                log.debug("Port sink closing listener for port %u", port)
                closesock(fd, sock)

        open_ports = [(tc, port, fd, sock) for tc, port, fd, sock in open_ports if now - tc < 5.0]

def nfq_handle(args, portqueue, notifyfd, donefd):
    from scapy.all import IP
    from netfilterqueue import NetfilterQueue

    def print_and_accept(pkt):
        pp = IP(pkt.get_payload())

        log.debug("NFQ sees packet from %s to port %u", pp.src, pp.dport)

        # tell portsink about this port
        portqueue.put(pp.dport)
        # notify it's select call
        os.write(notifyfd, "A")
        # wait for it to open the port
        os.read(donefd, 1)
        # push packet through
        pkt.accept()

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, print_and_accept)
    nfqueue.run()

def launchthread(fn, *args):
    t = threading.Thread(target=fn, args=args)
    t.daemon = True
    t.start()
    return t

def main():
    import argparse
    import Queue

    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser(description='Network sink, DHCP, DNS, fake services in a tiny sweet package.')
    parser.add_argument("--bind", help="IP address to bind for DNS and services.", default="192.168.56.1")
    args = parser.parse_args()

    dns_thread = launchthread(dns_serv, args)
    dhcp_thread = launchthread(dhcp_serv, args)

    q = Queue.Queue()
    notify_read, notify_write = os.pipe()
    done_read, done_write = os.pipe()

    portsink_thread = launchthread(port_sink, q, notify_read, done_write)
    nfq_handle(args, q, notify_write, done_read)

    return 0

if __name__ == '__main__':
    try: sys.exit(main())
    except (IOError, KeyboardInterrupt): pass
