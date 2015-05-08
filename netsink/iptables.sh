#!/bin/bash

for m in {D,A}; do
  for iface in {vboxnet0,qemubr}; do
	iptables -t nat -${m} PREROUTING -i $iface -p tcp -d 192.168.0.0/16 --dport 8019 -j ACCEPT
#	iptables -t nat -${m} PREROUTING -i $iface -p tcp -d 192.168.0.0/16 --dport 2042 -j ACCEPT

	iptables -t nat -${m} PREROUTING -i $iface -p udp -d 255.255.255.255 -j ACCEPT
	iptables -t nat -${m} PREROUTING -i $iface -p udp -d 192.168.0.0/16 --dport 67 -j ACCEPT
	iptables -t nat -${m} PREROUTING -i $iface -p udp -d 192.168.0.0/16 --dport 53 -j ACCEPT
  done

	iptables -t nat -${m} PREROUTING -i vboxnet0 -p udp -j DNAT --to-destination 192.168.56.1:1
	iptables -t nat -${m} PREROUTING -i vboxnet0 -p icmp -j DNAT --to-destination 192.168.56.1
	iptables -t nat -${m} PREROUTING -i vboxnet0 -p tcp -j DNAT --to-destination 192.168.56.1:1
	iptables -t nat -${m} PREROUTING -i qemubr -p udp -j DNAT --to-destination 192.168.55.1:1
	iptables -t nat -${m} PREROUTING -i qemubr -p icmp -j DNAT --to-destination 192.168.55.1
	iptables -t nat -${m} PREROUTING -i qemubr -p tcp -j DNAT --to-destination 192.168.55.1:1
done
