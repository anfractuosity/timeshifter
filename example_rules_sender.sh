#/bin/bash

iptables -F
iptables -X

iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP

iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -j DROP

iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type echo-request -j NFQUEUE --queue-num 0
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
