#!/bin/bash

# ---------- COLORES ---------- #
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 6)
MAGENTA=$(tput setaf 5)
RESET=$(tput sgr0)

# ---------- VARIABLES ---------- #
INPUT_DIR_MAPPERS="./traffic/mappers"
INPUT_DIR_DOS="./traffic/dos"
INPUT_DIR_BRUTE="./traffic/brute"
INPUT_DIR_NORMAL="./traffic/normal"
OUTPUT_DIR="./csvs"
TIPOS_MAPPERS=("nmap_ack" "nmap_connect" "nmap_fin" "nmap_os" "nmap_syn" "nmap_version" "nmap_xmas" "nmap_udp")
TIPOS_DOS=("dos_http" "dos_syn_flood" "dos_rst_flood" "dos_icmp_flood" "dos_udp_flood" "dos_flood_combo")
TIPOS_BRUTE=("brute_ftp" "brute_ssh" "brute_http" "brute_smb" "brute_rdp")
TIPOS_NORMAL=("normal_ftp" "normal_ssh" "normal_scp" "normal_http" "normal_smb" "normal_rdp" "normal_icmp" "normal_dns")

trap ctrl_c INT
tput civis;

function ctrl_c() {
    echo -e "${RED}\n[*] Exiting... ${RESET}"
    tput cnorm; exit 0
}

function clean_output_dir(){
    echo "${YELLOW}[*] Limpiando CSVs anteriores... ${RESET}"
    rm -f $OUTPUT_DIR/*.csv
}

function clean_temp_files(){
    local tipo="$1"
    local dir="$2"
    rm -f "$dir/${tipo}_all.pcap" "$dir/${tipo}_filtered.pcap" "$dir/${tipo}.argus"
}

# Únicamente usada para testear
function get_bidir_flag(){
    local tipo="$1"
    case "$tipo" in
        nmap_udp | dos_syn_flood | dos_rst_flood | dos_icmp_flood | dos_udp_flood | dos_flood_combo )
            echo ""
            ;;
        *)
            echo "--bidir"  # DEFAULT
            ;;
    esac
}

function generar_csv(){
    local tipo="$1"
    local dir="$2"
    local label="$3"
    local attack_type="$4"
    local attack_category="$5"
    local bidir="$(get_bidir_flag "$tipo")"

    argus -r "$dir/${tipo}_filtered.pcap" -w "$dir/${tipo}.argus" > /dev/null

    ra -n -r "$dir/${tipo}.argus" \
        -s saddr daddr sport dport proto state dur pkts bytes sbytes dbytes spkts dpkts rate srate drate load sload dload smeansz dmeansz \
        -c "," > "$OUTPUT_DIR/${tipo}.csv"

    echo "${YELLOW}[*] Fusionando flows + flags TCP ${RESET}"
    python3 tcpFlags.py "$OUTPUT_DIR/${tipo}.csv" "$OUTPUT_DIR/${tipo}_tcpflags.csv" "$OUTPUT_DIR/${tipo}_merged.csv" "--bidir" #Le meto siempre bidir por uniformidad
	
    # Corrección para dos_icmp_flood y normal_icmp: Sport y Dport a -1
    if [[ "$tipo" == "dos_icmp_flood" || "$tipo" == "normal_icmp" ]]; then
        echo "${MAGENTA}    [ICMP] Estableciendo Sport/Dport = -1 ${RESET}"
        python3 <<-EOF
		import pandas as pd
		df = pd.read_csv('$OUTPUT_DIR/${tipo}_merged.csv')
		df['Sport'] = -1
		df['Dport'] = -1
		df.to_csv('$OUTPUT_DIR/${tipo}_merged.csv', index=False)
		EOF
    fi

	# Corrección para dos_udp_flood: Dport vacío a 0
    if [[ "$tipo" == "dos_udp_flood" ]]; then
        echo "${MAGENTA}    [UDP] Estableciendo Dport = 0 donde está vacío ${RESET}"
    	python3 <<-EOF
		import pandas as pd
		df = pd.read_csv('$OUTPUT_DIR/${tipo}_merged.csv')
		df['Dport'] = df['Dport'].fillna(0)
		df.loc[df['Dport'].astype(str).str.strip() == '', 'Dport'] = 0
		df.to_csv('$OUTPUT_DIR/${tipo}_merged.csv', index=False)
		EOF
    fi

    # Corrección para dos_udp_flood y dos_flood_combo: Eliminar flujo con Sport o Dport NaN
    if [[ "$tipo" == "dos_udp_flood" || "$tipo" == "dos_flood_combo" ]]; then
        echo "${MAGENTA}    [UDP/COMBO] Eliminando flows con Sport o Dport NaN ${RESET}"
        python3 <<-EOF
		import pandas as pd
		df = pd.read_csv('$OUTPUT_DIR/${tipo}_merged.csv')
		df = df[df['Sport'].notna()]
		df = df[df['Dport'].notna()]
		df.to_csv('$OUTPUT_DIR/${tipo}_merged.csv', index=False)
		EOF
    fi

	# Corrección para nmap_udp: Eliminar flujo con Sport o Dport vacío
    if [[ "$tipo" == "nmap_udp" ]]; then
        echo "${MAGENTA}    [UDP] Eliminando flows con Sport o Dport vacíos ${RESET}"
    	python3 <<-EOF
		import pandas as pd
		df = pd.read_csv('$OUTPUT_DIR/${tipo}_merged.csv')
		df = df[df['Sport'].notna() & df['Dport'].notna()]
		df = df[df['Sport'].astype(str).str.strip() != '']
		df = df[df['Dport'].astype(str).str.strip() != '']
		df.to_csv('$OUTPUT_DIR/${tipo}_merged.csv', index=False)
		EOF
    fi

    echo "${YELLOW}[*] Añadiendo columnas: label, attack_type, attack_category ${RESET}"
    awk -v tipo="$attack_type" -v label="$label" -v cat="$attack_category" 'BEGIN {FS=OFS=","} NR==1 {print $0, "label", "attack_type", "attack_category"; next} {print $0, label, tipo, cat}' "$OUTPUT_DIR/${tipo}_merged.csv" > "$OUTPUT_DIR/${tipo}_final.csv"
}

clean_output_dir

## ---------- MAPPERS ---------- ##
echo "[>] Etiquetando MAPPERS"
for tipo in "${TIPOS_MAPPERS[@]}"
do
    echo "${BLUE}[*] Procesando $tipo ${RESET}"
    clean_temp_files "$tipo" "$INPUT_DIR_MAPPERS"

    mergecap -F pcap -w "$INPUT_DIR_MAPPERS/${tipo}_all.pcap" "$INPUT_DIR_MAPPERS/${tipo}"*.pcap

    echo "${MAGENTA}    [Filtro] DNS + ICMP ${RESET}"
    tshark -r "$INPUT_DIR_MAPPERS/${tipo}_all.pcap" \
        -Y "frame.protocols contains ip and not dns and not icmp" \
        -w "$INPUT_DIR_MAPPERS/${tipo}_filtered.pcap" 2>/dev/null

    if [[ "$tipo" == "nmap_udp" ]]; then
        echo "${MAGENTA}    [UDP] Sin extracción de flags TCP ${RESET}"
        > "$OUTPUT_DIR/${tipo}_tcpflags.csv"
    else
        echo "${MAGENTA}    [TCP] Extrayendo flags TCP ${RESET}"
        tshark -r "$INPUT_DIR_MAPPERS/${tipo}_filtered.pcap" \
            -Y "tcp" -T fields -E separator=, -E header=y \
            -e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags \
            > "$OUTPUT_DIR/${tipo}_tcpflags.csv" 2>/dev/null
    fi

    generar_csv "$tipo" "$INPUT_DIR_MAPPERS" 1 "$tipo" "scan"
    echo "${GREEN}[+] CSV listo: $OUTPUT_DIR/${tipo}_final.csv ${RESET}"
done

## ---------- DOS ---------- ##
echo "[>] Etiquetando DOS"
for tipo in "${TIPOS_DOS[@]}"
do
    echo "${BLUE}[*] Procesando $tipo ${RESET}"
    clean_temp_files "$tipo" "$INPUT_DIR_DOS"

    mergecap -F pcap -w "$INPUT_DIR_DOS/${tipo}_all.pcap" "$INPUT_DIR_DOS/${tipo}"*.pcap

    if [[ "$tipo" == "dos_icmp_flood" ]]; then
        echo "${MAGENTA}    [ICMP] Filtrando DNS ${RESET}"
        tshark -r "$INPUT_DIR_DOS/${tipo}_all.pcap" \
            -Y "frame.protocols contains ip and not dns" \
            -w "$INPUT_DIR_DOS/${tipo}_filtered.pcap" 2>/dev/null
    else
        echo "${MAGENTA}    [Filtro] DNS + ICMP ${RESET}"
        tshark -r "$INPUT_DIR_DOS/${tipo}_all.pcap" \
            -Y "frame.protocols contains ip and not dns and not icmp" \
            -w "$INPUT_DIR_DOS/${tipo}_filtered.pcap" 2>/dev/null
    fi

    if [[ "$tipo" == "dos_udp_flood" || "$tipo" == "dos_icmp_flood" || "$tipo" == "dos_flood_combo" ]]; then
        echo "${MAGENTA}    [UDP/ICMP/COMBO] Sin extracción de flags TCP ${RESET}"
        > "$OUTPUT_DIR/${tipo}_tcpflags.csv"
    else
        echo "${MAGENTA}    [TCP] Extrayendo flags TCP ${RESET}"
        tshark -r "$INPUT_DIR_DOS/${tipo}_filtered.pcap" \
            -Y "tcp" -T fields -E separator=, -E header=y \
            -e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags \
            > "$OUTPUT_DIR/${tipo}_tcpflags.csv" 2>/dev/null
    fi

    generar_csv "$tipo" "$INPUT_DIR_DOS" 1 "$tipo" "dos"
    echo "${GREEN}[+] CSV listo: $OUTPUT_DIR/${tipo}_final.csv ${RESET}"
done

## ---------- BRUTE ---------- ##
echo "[>] Etiquetando BRUTE"
for tipo in "${TIPOS_BRUTE[@]}"
do
    echo "${BLUE}[*] Procesando $tipo ${RESET}"
    clean_temp_files "$tipo" "$INPUT_DIR_BRUTE"

    mergecap -F pcap -w "$INPUT_DIR_BRUTE/${tipo}_all.pcap" "$INPUT_DIR_BRUTE/${tipo}"*.pcap

    echo "${MAGENTA}    [Filtro] DNS + ICMP ${RESET}"
    tshark -r "$INPUT_DIR_BRUTE/${tipo}_all.pcap" \
        -Y "frame.protocols contains ip and not dns and not icmp" \
        -w "$INPUT_DIR_BRUTE/${tipo}_filtered.pcap" 2>/dev/null
    
    echo "${MAGENTA}    [TCP] Extrayendo flags TCP ${RESET}"
    tshark -r "$INPUT_DIR_BRUTE/${tipo}_filtered.pcap" \
        -Y "tcp" -T fields -E separator=, -E header=y \
        -e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags \
         > "$OUTPUT_DIR/${tipo}_tcpflags.csv" 2>/dev/null

    generar_csv "$tipo" "$INPUT_DIR_BRUTE" 1 "$tipo" "brute"
    echo "${GREEN}[+] CSV listo: $OUTPUT_DIR/${tipo}_final.csv ${RESET}"
done

## ---------- NORMAL ---------- ##
echo "[>] Etiquetando NORMAL"
for tipo in "${TIPOS_NORMAL[@]}"
do
    echo "${BLUE}[*] Procesando $tipo ${RESET}"
    clean_temp_files "$tipo" "$INPUT_DIR_NORMAL"

    mergecap -F pcap -w "$INPUT_DIR_NORMAL/${tipo}_all.pcap" "$INPUT_DIR_NORMAL/${tipo}"*.pcap

    if [[ "$tipo" == "normal_icmp" ]]; then
		echo "${MAGENTA}    [ICMP] Filtrando DNS ${RESET}"
		tshark -r "$INPUT_DIR_NORMAL/${tipo}_all.pcap" \
		    -Y "icmp and not dns" \
		    -w "$INPUT_DIR_NORMAL/${tipo}_filtered.pcap" 2>/dev/null

	elif [[ "$tipo" == "normal_dns" ]]; then
		echo "${MAGENTA}    [DNS] Filtrando solo UDP ${RESET}"
		tshark -r "$INPUT_DIR_NORMAL/${tipo}_all.pcap" \
		    -Y "udp.port == 53 and not icmp" \
		    -w "$INPUT_DIR_NORMAL/${tipo}_filtered.pcap" 2>/dev/null

	else
		echo "${MAGENTA}    [TCP] Filtrando solo tráfico TCP ${RESET}"
		tshark -r "$INPUT_DIR_NORMAL/${tipo}_all.pcap" \
		    -Y "tcp" \
		    -w "$INPUT_DIR_NORMAL/${tipo}_filtered.pcap" 2>/dev/null
	fi
	
    if [[ "$tipo" == "normal_icmp" || "$tipo" == "normal_dns" ]]; then
        echo "${MAGENTA}    [ICMP] Sin extracción de flags TCP ${RESET}"
        > "$OUTPUT_DIR/${tipo}_tcpflags.csv"
    else
        echo "${MAGENTA}    [TCP] Extrayendo flags TCP ${RESET}"
        tshark -r "$INPUT_DIR_NORMAL/${tipo}_filtered.pcap" \
            -Y "tcp" -T fields -E separator=, -E header=y \
            -e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags \
            > "$OUTPUT_DIR/${tipo}_tcpflags.csv" 2>/dev/null
    fi

    generar_csv "$tipo" "$INPUT_DIR_NORMAL" 0 "$tipo" "normal"
    echo "${GREEN}[+] CSV listo: $OUTPUT_DIR/${tipo}_final.csv ${RESET}"
done

echo "${GREEN}[*] Unificando dataset final ${RESET}"
head -n 1 "$OUTPUT_DIR/${TIPOS_NORMAL[0]}_final.csv" > "$OUTPUT_DIR/dataset.csv"
tail -n +2 -q "$OUTPUT_DIR/"*_final.csv >> "$OUTPUT_DIR/dataset.csv"
echo "${GREEN}[+] Dataset unificado: $OUTPUT_DIR/dataset.csv${RESET}"

tput cnorm
