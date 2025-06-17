#!/bin/bash

set -euo pipefail

# ---------- COLORES ---------- #
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 6)
MAGENTA=$(tput setaf 5)
RESET=$(tput sgr0)

# ---------- VARIABLES ---------- #
INPUT_DIR="./traffic"
OUTPUT_DIR="./csvs"
ZEEK_LOG_DIR="./zeek_logs"

INPUT_DIR_MAPPERS="./traffic/mappersNew"
INPUT_DIR_NORMAL="./traffic/normal"

TIPOS_MAPPERS=("nmap_ack" "nmap_connect" "nmap_fin" "nmap_syn" "nmap_xmas" "nmap_null")
TIPOS_NORMAL=("normal_ftp" "normal_ssh" "normal_scp" "normal_http" "normal_smb" "normal_rdp" "normal_icmp" "normal_dns")

trap ctrl_c INT
tput civis

function ctrl_c() {
    echo -e "${RED}\n[*] Saliendo...${RESET}"
    tput cnorm
    exit 0
}

function clean_output_dir(){
    echo "${YELLOW}[*] Limpiando CSVs anteriores...${RESET}"
    rm -f $OUTPUT_DIR/*.csv 2>/dev/null || true
    rm -rf $ZEEK_LOG_DIR/* 2>/dev/null || true
}

function clean_temp_files(){
    local base="$1"
    rm -f "${base}_all.pcap" "${base}_filtered.pcap"
}

function get_filter() {
    echo "frame.protocols contains ip"
}

function run_zeek_and_parse() {
    local tipo="$1"
    local pcap="$2"
    local label="$3"
    local attack_type="$4"
    local attack_category="$5"
    local zeek_dir="${ZEEK_LOG_DIR}/${tipo}"

    mkdir -p "$zeek_dir"
    echo "${MAGENTA}[*] Ejecutando Zeek para $tipo...${RESET}"
    zeek -C -r "$pcap" || echo "${RED}[!] Zeek falló para $tipo${RESET}"

    mv conn.log "$zeek_dir/conn.log"

    python3 zeekParser.py "$zeek_dir/conn.log" "$OUTPUT_DIR/${tipo}_final.csv" "$tipo" "$label" "$attack_type" "$attack_category"
}

function generate_csv(){
    local tipo="$1"
    local label="$2"
    local attack_type="$3"
    local attack_category="$4"

    local base_dir
    case "$tipo" in
        nmap_*) base_dir="$INPUT_DIR_MAPPERS" ;;
        dos_*) base_dir="$INPUT_DIR_DOS" ;;
        brute_*) base_dir="$INPUT_DIR_BRUTE" ;;
        normal_*) base_dir="$INPUT_DIR_NORMAL" ;;
        *) echo "${RED}[!] Tipo desconocido: $tipo${RESET}" ; return ;;
    esac

    local FILTER
    FILTER="$(get_filter "$tipo")"
    echo "${MAGENTA}[Filtro adaptado] $FILTER${RESET}"

    if ! ls "${base_dir}/${tipo}"*.pcap &> /dev/null; then
        echo "${RED}[!] No hay PCAPs para ${tipo} en ${base_dir}, saltando...${RESET}"
        return
    fi

    local pcap_all="${base_dir}/${tipo}_all.pcap"
    local pcap_filtered="${base_dir}/${tipo}_filtered.pcap"

    mergecap -F pcap -w "$pcap_all" "${base_dir}/${tipo}"*.pcap
    tshark -r "$pcap_all" -Y "$FILTER" -w "$pcap_filtered" 2>/dev/null

    run_zeek_and_parse "$tipo" "$pcap_filtered" "$label" "$attack_type" "$attack_category"

    local lines
    lines=$(wc -l < "$OUTPUT_DIR/${tipo}_final.csv")
    echo "${GREEN}[✓] Procesado $tipo: $((lines - 1)) flujos añadidos${RESET}"
}

# ---------- INICIO LIMPIEZA ---------- #
clean_output_dir

# ---------- MAPPERS ---------- #
echo "[>] Etiquetando MAPPERS"
for tipo in "${TIPOS_MAPPERS[@]}"; do
    echo "${BLUE}[*] Procesando $tipo${RESET}"
    clean_temp_files "$INPUT_DIR_MAPPERS/$tipo"
    generate_csv "$tipo" 1 "$tipo" "scan"
done

# ---------- NORMAL ---------- #
echo "[>] Etiquetando NORMAL"
for tipo in "${TIPOS_NORMAL[@]}"; do
    echo "${BLUE}[*] Procesando $tipo${RESET}"
    clean_temp_files "$INPUT_DIR_NORMAL/$tipo"
    generate_csv "$tipo" 0 "$tipo" "normal"
done

# ---------- UNIFICACIÓN ---------- #
echo "${GREEN}[*] Unificando dataset final${RESET}"
head -n 1 "$OUTPUT_DIR/${TIPOS_NORMAL[0]}_final.csv" > "$OUTPUT_DIR/dataset.csv"
tail -n +2 -q "$OUTPUT_DIR/"*_final.csv >> "$OUTPUT_DIR/dataset.csv"
echo "${GREEN}[+] Dataset final: $OUTPUT_DIR/dataset.csv${RESET}"

tput cnorm