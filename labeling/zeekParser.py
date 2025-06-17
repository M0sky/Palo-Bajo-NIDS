import pandas as pd
import sys

def safe_port_conversion(val):
    try:
        if isinstance(val, str) and val.startswith("0x"):
            return int(val, 16)
        return int(val)
    except:
        return -1  # valor inválido

def parse_zeek_time(ts):
    try:
        return float(ts)
    except:
        return 0.0

def main(zeek_conn_log, output_csv, tipo, label, attack_type, attack_category):
    print(f"[*] Cargando Zeek: {zeek_conn_log}")
    zeek_flows = []

    with open(zeek_conn_log, 'r') as f:
        headers = []
        for line in f:
            if line.startswith("#fields"):
                headers = line.strip().split("\t")[1:]
                continue
            if line.startswith("#") or not line.strip():
                continue
            values = line.strip().split("\t")
            row = dict(zip(headers, values))

            duration = parse_zeek_time(row.get('duration', '0'))
            orig_bytes = float(row.get('orig_ip_bytes', '0'))
            resp_bytes = float(row.get('resp_ip_bytes', '0'))
            orig_pkts = float(row.get('orig_pkts', '0'))
            resp_pkts = float(row.get('resp_pkts', '0'))

            if duration == 0.0 and orig_bytes > 0 and resp_bytes > 0 and orig_pkts > 0 and resp_pkts > 0:
                duration = 0.001

            tot_pkts = orig_pkts + resp_pkts
            tot_bytes = orig_bytes + resp_bytes

            rate = tot_bytes / duration if duration > 0 else 0
            srate = orig_bytes / duration if duration > 0 else 0
            drate = resp_bytes / duration if duration > 0 else 0

            load = rate * 8
            sload = srate * 8
            dload = drate * 8

            smeansz = orig_bytes / orig_pkts if orig_pkts > 0 else 0
            dmeansz = resp_bytes / resp_pkts if resp_pkts > 0 else 0

            zeek_flows.append({
                'SrcAddr': row.get('id.orig_h', ''),
                'DstAddr': row.get('id.resp_h', ''),
                'Sport': safe_port_conversion(row.get('id.orig_p', -1)),
                'Dport': safe_port_conversion(row.get('id.resp_p', -1)),
                'Proto': row.get('proto', '').lower(),
                'State': row.get('conn_state', ''),
                'Dur': duration,
                'TotPkts': tot_pkts,
                'TotBytes': tot_bytes,
                'SrcBytes': orig_bytes,
                'DstBytes': resp_bytes,
                'SrcPkts': orig_pkts,
                'DstPkts': resp_pkts,
                'Rate': rate,
                'SrcRate': srate,
                'DstRate': drate,
                'Load': load,
                'SrcLoad': sload,
                'DstLoad': dload,
                'sMeanPktSz': smeansz,
                'dMeanPktSz': dmeansz,
                'conn_state': row.get('conn_state', ''),
                'history': row.get('history', ''),
                'label': int(label),
                'attack_type': attack_type,
                'attack_category': attack_category
            })

    df = pd.DataFrame(zeek_flows)
    print(f"[*] Guardando CSV final: {output_csv}")
    df.to_csv(output_csv, index=False)

if __name__ == "__main__":
    if len(sys.argv) != 7:
        print("Uso: python3 zeekParser.py <zeek_conn.log> <output.csv> <tipo> <label> <attack_type> <attack_category>")
        sys.exit(1)

    main(*sys.argv[1:])