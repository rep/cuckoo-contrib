iptables -t nat -A PREROUTING -i vboxnet0 -p tcp -j DNAT --to-destination 192.168.56.1
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
# resultserver bypass
iptables -A INPUT -i vboxnet0 -p tcp --dport 2042 -j ACCEPT
iptables -A INPUT -i vboxnet0 -p tcp -j NFQUEUE --queue-num 1
