#!/bin/bash

DEBUG=0
if [[ "$1" == "--debug" ]]; then
    DEBUG=1
fi

echo "[*] Parando procesos Kafka y Zookeeper..."
pkill -f kafka.Kafka
pkill -f zookeeper
pkill -f ConsoleConsumer
pkill -f suricata
pkill -f zeekctl
pkill -f td-agent-bit
sleep 3

echo "[*] Limpiando logs..."
rm -rf /tmp/kafka-logs /tmp/zookeeper

echo "[*] Iniciando Zookeeper..."
nohup /opt/kafka/bin/zookeeper-server-start.sh /opt/kafka/config/zookeeper.properties > /tmp/zookeeper.log 2>&1 &
sleep 5

echo "[*] Iniciando Kafka..."
nohup /opt/kafka/bin/kafka-server-start.sh /opt/kafka/config/server.properties > /tmp/kafka.log 2>&1 &
sleep 10

echo "[*] Borrando tópicos..."
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --delete --topic zeek-flows 2>/dev/null
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --delete --topic suricata-flows 2>/dev/null
sleep 2

echo "[*] Recreando tópicos:"
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --create --topic zeek-flows --partitions 1 --replication-factor 2>/dev/null
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --create --topic suricata-flows --partitions 1 --replication-factor 2>/dev/null

echo "[*] Estado actual de los tópicos:"
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list 2>/dev/null
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --describe --topic zeek-flows 2>/dev/null
/opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --describe --topic suricata-flows 2>/dev/null

echo "[*] Lanzando Fluent Bit..."
nohup td-agent-bit -c /etc/td-agent-bit/td-agent-bit.conf > /tmp/td-agent-bit.log 2>&1 &

echo "[*] Iniciando Suricata en ens33..."
nohup suricata -c /etc/suricata/suricata.yaml -i ens33 > /tmp/suricata.log 2>&1 &

echo "[*] Iniciando Zeek..."
zeekctl deploy > /dev/null 2>&1

echo "[*] AI loading..."
if [[ $DEBUG -eq 1 ]]; then
    python3 myVerbraucher.py --debug
else
    python3 myVerbraucher.py 2>/dev/null
fi