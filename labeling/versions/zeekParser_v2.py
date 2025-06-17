import pandas as pd
import sys
import os

def safe_port_conversion(val):
    try:
        if isinstance(val, str) and val.startswith("0x"):
            return int(val, 16)
        return int(val)
    except:
        return -1  # valor inválido

def main(argus_csv, zeek_conn_log, output_csv):
    print(f"[*] Cargando Argus: {argus_csv}")
    df = pd.read_csv(argus_csv, low_memory=False)

    df["Sport"] = df.get("Sport", -1).apply(safe_port_conversion)
    df["Dport"] = df.get("Dport", -1).apply(safe_port_conversion)

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
            zeek_flows.append({
                'id_orig_h': row.get('id.orig_h', ''),
                'id_resp_h': row.get('id.resp_h', ''),
                'id_orig_p': safe_port_conversion(row.get('id.orig_p', -1)),
                'id_resp_p': safe_port_conversion(row.get('id.resp_p', -1)),
                'proto': row.get('proto', '').lower(),
                'conn_state': row.get('conn_state', ''),
                'history': row.get('history', '')
            })

    zeek_df = pd.DataFrame(zeek_flows)

    merged = pd.merge(
        df,
        zeek_df,
        how="left",
        left_on=["SrcAddr", "DstAddr", "Sport", "Dport", "Proto"],
        right_on=["id_orig_h", "id_resp_h", "id_orig_p", "id_resp_p", "proto"]
    )

    merged.drop(columns=["id_orig_h", "id_resp_h", "id_orig_p", "id_resp_p", "proto"], inplace=True)

    print(f"[*] Guardando CSV fusionado: {output_csv}")
    merged.to_csv(output_csv, index=False)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Uso: python3 zeekParser.py <argus.csv> <zeek_conn.log> <output.csv>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2], sys.argv[3])