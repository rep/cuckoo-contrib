iptables -t nat -A PREROUTING -i vboxnet0 -p tcp ! -d 192.168.56.1 -j DNAT --to-destination 192.168.56.1:1
iptables -t nat -A PREROUTING -i vboxnet0 -p tcp -d 192.168.56.1 ! --dport 2042 -j DNAT --to-destination 192.168.56.1:1

