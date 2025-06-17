#!/bin/bash

# Objetivo -> Enriquecer mi dataset
# Uso: ./scan_variants.sh <TIPO_ESCANEO> <IP_OBJETIVO>

TIPO_ESCANEO="$1"   # Ej: sA, sS, sT, sF, sX...
OBJETIVO="$2"       # Ej: 10.1.2.20

if [ -z "$TIPO_ESCANEO" ] || [ -z "$OBJETIVO" ]; then
    echo "Uso: $0 <tipo_escaneo> <ip_objetivo>"
    exit 1
fi

PORT_SETS=(
  "-p 1-1000"
  "--top-ports 1000"
  "-p 21,22,23,25,80,443,445,3389"
  "-p 135,139,445,3389"
  "-p 80,443"
)

OPTIONS=(
  "-T2"
  "-T4"
  "--data-length 25"
  "--data-length 50"
  "--badsum"
  "--mtu 24"
  "--ttl 33"
  "--ip-options R"
  "-f"
  "--spoof-mac 0"
  "--ttl 128 --window 4096"
  "--ttl 255 --window 1024"
  "--scan-delay 20ms"
  "--randomize-hosts"
  "--min-rate 10 --max-rate 50"
  "--min-rate 1000"
  "-D RND:5"
  "-D 192.168.1.1,10.0.0.1"
)

SCRIPTS=(
  "-sC"
  "--script=default,vuln"
  "--script=banner"
  "--script=ftp*"
)

EXTRAS=(
  "-sV"
  "-n"
  "--top-ports 500"
)

PN=(
  "nmap -Pn -$TIPO_ESCANEO --top-ports 1000 -T2 $OBJETIVO"
  "nmap -Pn -$TIPO_ESCANEO -p 80,443 --data-length 40 -T4 $OBJETIVO"
  "nmap -Pn -$TIPO_ESCANEO -p 21,22,23 --ttl 128 --spoof-mac Apple -T3 $OBJETIVO"
  "nmap -Pn -$TIPO_ESCANEO -f -p 135,139,445 --scan-delay 30ms $OBJETIVO"
  "nmap -Pn -$TIPO_ESCANEO -p 3389 --min-rate 20 --max-rate 60 --ip-options U -T2 $OBJETIVO"
  "nmap -Pn -$TIPO_ESCANEO --top-ports 500 -D RND:3 --data-length 50 -T3 $OBJETIVO"
)

run_nmap() {
  local cmd="$1"
  echo "[*] Ejecutando: $cmd"
  eval "$cmd" > /dev/null 2>&1
  sleep 2
}

for ports in "${PORT_SETS[@]}"; do
  for opt in "${OPTIONS[@]}"; do
    run_nmap "nmap -$TIPO_ESCANEO $ports $opt $OBJETIVO"
  done
        sleep 1
  for script in "${SCRIPTS[@]}"; do
    run_nmap "nmap -$TIPO_ESCANEO $ports -T3 $script $OBJETIVO"
  done
  for extra in "${EXTRAS[@]}"; do
    run_nmap "nmap -$TIPO_ESCANEO $ports $extra -T4 $OBJETIVO"
  done

  for pn_cmd in "${PN[@]}"; do
    run_nmap "$pn_cmd"
  done

run_nmap "nmap -$TIPO_ESCANEO $ports --data-length 40 -D 192.168.1.1 -T3 $OBJETIVO"
  run_nmap "nmap -$TIPO_ESCANEO --spoof-mac Apple -T3 --top-ports 500 $OBJETIVO"
  run_nmap "nmap -$TIPO_ESCANEO $ports -f --data-length 50 -D RND:5 --spoof-mac 0 -T2 $OBJETIVO"
  run_nmap "nmap -$TIPO_ESCANEO $ports -S 192.168.1.100 $OBJETIVO"
  run_nmap "nmap -sI zombiehost $OBJETIVO"
  run_nmap "nmap -sW $ports $OBJETIVO"
  run_nmap "nmap -sZ -p 21 $OBJETIVO"
  run_nmap "nmap -sR -p 111 $OBJETIVO"
  run_nmap "nmap -sU --top-ports 200 -T4 $OBJETIVO"
  run_nmap "nmap -$TIPO_ESCANEO $ports -n $OBJETIVO"
        sleep 2
        done

echo "[+] Escaneos para -$TIPO_ESCANEO completados contra $OBJETIVO."
exit 0