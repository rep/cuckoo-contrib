#!/bin/bash

iptables -F
iptables -t nat -F

OUT_DEVS="eth0 wlan0"
VBOXNET="192.168.56.0/24"

for i in $OUT_DEVS
	do iptables -t nat -A POSTROUTING -o $i -s $VBOXNET -j MASQUERADE
done

iptables -P FORWARD DROP	# default drop

# existing connections
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

# accept connections from VBOXNET to everything (DANGER, FULL INTERNET)
iptables -A FORWARD -s $VBOXNET -j ACCEPT

# want to redirect some ports?
#iptables -t nat -A PREROUTING -s $VBOXNET -p tcp --dport 80 -j DNAT --to-destination 192.168.56.1:80
#iptables -t nat -A PREROUTING -s $VBOXNET -p tcp --dport 25 -j DNAT --to-destination 192.168.56.1:25

# vm internal should be okay
iptables -A FORWARD -s 192.168.56.0/24 -d 192.168.56.0/24 -j ACCEPT

# log stuff that reaches this point (could be noisy)
iptables -A FORWARD -j LOG

# actually enable forwarding of packets
echo 1 > /proc/sys/net/ipv4/ip_forward

