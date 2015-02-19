for m in {D,A}; do
	iptables -t nat -${m} PREROUTING -i vboxnet0 -p tcp -d 192.168.56.1 --dport 2042 -j ACCEPT
	iptables -t nat -${m} PREROUTING -i vboxnet0 -p tcp -j DNAT --to-destination 192.168.56.1:1

	iptables -t nat -${m} PREROUTING -i vboxnet0 -p udp -d 255.255.255.255 -j ACCEPT
	iptables -t nat -${m} PREROUTING -i vboxnet0 -p udp -d 192.168.56.1 --dport 67 -j ACCEPT
	iptables -t nat -${m} PREROUTING -i vboxnet0 -p udp -d 192.168.56.1 --dport 53 -j ACCEPT
	iptables -t nat -${m} PREROUTING -i vboxnet0 -p udp -j DNAT --to-destination 192.168.56.1:1
done
