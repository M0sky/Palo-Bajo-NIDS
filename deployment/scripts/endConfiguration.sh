#!/bin/bash
echo "[*] Parando procesos..."
pkill -f kafka.Kafka
pkill -f zookeeper
pkill -f ConsoleConsumer
pkill -f suricata
pkill -f zeekctl
pkill -f td-agent-bit

IP="10.1.1.10"

echo "[*] Desbloqueando IP $IP..."

iptables -D INPUT -s $IP -j DROP
iptables -D OUTPUT -d $IP -j DROP
iptables -D FORWARD -s $IP -j DROP
iptables -D FORWARD -d $IP -j DROP

echo "[+] IP $IP desbloqueada!"
