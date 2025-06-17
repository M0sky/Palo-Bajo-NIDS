#!/usr/bin/env python3

import pandas as pd
import sys
import os

# Diccionario de flags TCP
TCP_FLAGS = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
    0x40: "ECE",
    0x80: "CWR"
}

def decode_flags(value):
    try:
        value = int(str(value), 0)
    except:
        return "NONE"
    flags = [name for bit, name in sorted(TCP_FLAGS.items()) if value & bit]
    return "+".join(flags) if flags else "NONE"

def main(argus_csv, tshark_csv, output_csv, use_bidir=False):
    print(f"[*] Cargando CSV de Argus: {argus_csv}")
    df_argus = pd.read_csv(argus_csv, low_memory=False)

    if os.stat(tshark_csv).st_size == 0:
        print("[!] CSV de flags vacío ~ UDP/ICMP")
        df_argus["tcp.flags.decoded"] = ""
        for flag in TCP_FLAGS.values():
            df_argus[f"has_{flag}"] = False
        df_argus.to_csv(output_csv, index=False)
        return

    print(f"[*] Cargando CSV de TShark: {tshark_csv}")
    df_tshark = pd.read_csv(tshark_csv)
    df_tshark["tcp.flags.decoded"] = df_tshark["tcp.flags"].apply(decode_flags)

    for col in ["tcp.srcport", "tcp.dstport"]:
        df_tshark[col] = pd.to_numeric(df_tshark[col], errors="coerce")

    df_tshark.dropna(subset=["ip.src", "ip.dst", "tcp.srcport", "tcp.dstport"], inplace=True)

    if use_bidir:
        print("[*] Usando flow_id BIDIRECCIONAL")
        df_tshark["flow_id"] = df_tshark.apply(
            lambda row: tuple(sorted([
                (row["ip.src"], int(row["tcp.srcport"])),
                (row["ip.dst"], int(row["tcp.dstport"]))
            ])), axis=1
        )
    else:
        print("[*] Usando flow_id UNIDIRECCIONAL")
        df_tshark["flow_id"] = df_tshark.apply(
            lambda row: (
                row["ip.src"], int(row["tcp.srcport"]),
                row["ip.dst"], int(row["tcp.dstport"])
            ), axis=1
        )

    df_flags_grouped = (
        df_tshark.groupby("flow_id")["tcp.flags.decoded"]
        .apply(lambda x: "+".join(sorted(set("+".join(x).split("+")))))
        .reset_index()
    )

    if use_bidir:
        df_flags_grouped[["SrcAddr", "Sport"]] = pd.DataFrame(
            df_flags_grouped["flow_id"].apply(lambda x: x[0]).tolist(), index=df_flags_grouped.index)
        df_flags_grouped[["DstAddr", "Dport"]] = pd.DataFrame(
            df_flags_grouped["flow_id"].apply(lambda x: x[1]).tolist(), index=df_flags_grouped.index)
    else:
        df_flags_grouped[["SrcAddr", "Sport", "DstAddr", "Dport"]] = pd.DataFrame(
            df_flags_grouped["flow_id"].tolist(), index=df_flags_grouped.index)


    print(f"[i] Total flows con flags TCP: {len(df_flags_grouped)}")
    df_flags_grouped.drop(columns=["flow_id"], inplace=True)

    for col in ["Sport", "Dport"]:
        df_argus[col] = pd.to_numeric(df_argus[col], errors="coerce")
        df_flags_grouped[col] = pd.to_numeric(df_flags_grouped[col], errors="coerce")

    df_argus.dropna(subset=["SrcAddr", "DstAddr", "Sport", "Dport"], inplace=True)
    df_flags_grouped.dropna(subset=["SrcAddr", "DstAddr", "Sport", "Dport"], inplace=True)

    df_final = pd.merge(df_argus, df_flags_grouped, how="left", on=["SrcAddr", "DstAddr", "Sport", "Dport"])

    df_final["tcp.flags.decoded"] = df_final["tcp.flags.decoded"].fillna("")
    for flag in TCP_FLAGS.values():
        df_final[f"has_{flag}"] = df_final["tcp.flags.decoded"].apply(lambda flags: flag in flags.split("+"))

    df_final["num_flags_tcp"] = df_final[[f"has_{flag}" for flag in TCP_FLAGS.values()]].sum(axis=1)

    df_final.to_csv(output_csv, index=False)

if __name__ == "__main__":
    if len(sys.argv) < 4 or len(sys.argv) > 5:
        print(f"Uso: {sys.argv[0]} <argus.csv> <tshark.csv> <output.csv> [--bidir]")
        sys.exit(1)

    use_bidir = len(sys.argv) == 5 and sys.argv[4] == "--bidir"
    main(sys.argv[1], sys.argv[2], sys.argv[3], use_bidir)