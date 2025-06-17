import os
import sys
import json
import numpy as np
import pandas as pd
import pickle
import tensorflow as tf
import subprocess
import threading

from datetime import datetime
from kafka import KafkaConsumer
from sklearn.preprocessing import LabelEncoder
from joblib import load
from dateutil import parser

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
blockedIPs = set()

# Cargar componentes del modelo
model = tf.keras.models.load_model("modelo_FINAL.keras")
preprocessing = load("preprocessing_pipeline_FINAL.pkl")
label_encoder = load("label_encoder_FINAL.pkl")
input_features = pickle.load(open("input_features_FINAL.pkl", "rb"))
numeric_real = pickle.load(open("numeric_features_FINAL.pkl", "rb"))

DEBUG = False
if len(sys.argv) > 1 and sys.argv[1] == "--debug":
    DEBUG = True

def blockIP(ip, duration=300):
    if ip in blockedIPs:
        if DEBUG:
            print(f"[+] {ip} already blocked!")
        return

    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
        subprocess.run(["iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"], check=True)
        subprocess.run(["iptables", "-A", "FORWARD", "-d", ip, "-j", "DROP"], check=True)
        blockedIPs.add(ip)
        if DEBUG:
            print(f"[+] IP {ip} blocked {duration} seconds")

        timer = threading.Timer(duration, unblockIP, args=[ip])
        timer.start()

    except subprocess.CalledProcessError as e:
        print(f"[!] Cant block {ip}: {e}")

def unblockIP(ip):
    try:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
        subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], check=True)
        subprocess.run(["iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"], check=True)
        blockedIPs.discard(ip)
        if DEBUG:
            print(f"[+] IP {ip} unblocked")

    except subprocess.CalledProcessError as e:
        print(f"[!] Cant unblock {ip}: {e}")

def reconstruct_flags(zeek, suri):
    history = (zeek.get("history") or "").upper()

    return {
        'has_SYN': int('S' in history),
        'has_ACK': int('A' in history),
        'has_RST': int('R' in history),
        'has_FIN': int('F' in history),
        'has_PSH': int('P' in history),
        'has_URG': int('U' in history),
        'has_ECE': int('E' in history),
        'has_CWR': int('C' in history),
    }

# Fusionar flujos Zeek + Suricata (PRIORIZAR ZEEK POR INCOSISTENCIA DE TIMEOUTS CON SURI)
def combine_flows(zeek, suri):
    try:
        proto = (zeek.get("proto") or "").lower()
        conn_state = str(zeek.get("conn_state") or "nan")
        history = str(zeek.get("history") or "").upper()

        suri_flow = suri.get("flow", {})

        pkts_to = float(zeek.get("orig_pkts", 0.0))
        pkts_from = float(zeek.get("resp_pkts", 0.0))

        # Si ambos son cero, tiro de Suricata
        if pkts_to == 0 and pkts_from == 0:
            if DEBUG:
                print(f"[!] WARNING: Faltan pkts: src{pkts_to} dst {pkts_from}")
            pkts_to = float(suri_flow.get("pkts_toserver", 0.0))
            pkts_from = float(suri_flow.get("pkts_toclient", 0.0))

        bytes_to = float(zeek.get("orig_bytes", 0.0))
        bytes_from = float(zeek.get("resp_bytes", 0.0))

        # Si ambos son cero, tiro de Suricata
        if bytes_to == 0 and bytes_from == 0:
            if DEBUG:
                print(f"[!] WARNING: Faltan bytes: src {bytes_to} dst {bytes_from}")
            bytes_to = float(suri_flow.get("bytes_toserver", 0.0))
            bytes_from = float(suri_flow.get("bytes_toclient", 0.0))

        tot_pkts = pkts_to + pkts_from
        tot_bytes = bytes_to + bytes_from

        sMeanPktSz = bytes_to / pkts_to if pkts_to > 0 else 0.0
        dMeanPktSz = bytes_from / pkts_from if pkts_from > 0 else 0.0

        duration = float(zeek.get("duration", 0.0))

        if duration == 0.0 and pkts_to > 0 and pkts_from > 0 and bytes_to > 0 and bytes_from > 0:
            duration = 0.001

        byte_ratio = bytes_to / bytes_from if bytes_from > 0 else 0
        pkt_ratio = pkts_to / pkts_from if pkts_from > 0 else 0

        rate = tot_bytes / duration if duration > 0 else 0
        src_rate = bytes_to / duration if duration > 0 else 0
        dst_rate = bytes_from / duration if duration > 0 else 0

        load = rate * 8 if rate >= 0 else 0
        src_load = src_rate / duration if duration > 0 else 0
        dst_load = dst_rate / duration if duration > 0 else 0

        pkts_per_sec = tot_pkts / duration if duration > 0 else 0
        bytes_per_sec = tot_bytes / duration if duration > 0 else 0

        proto_features = {
            "Proto_icmp": int(proto == "icmp"),
            "Proto_tcp": int(proto == "tcp"),
            "Proto_udp": int(proto == "udp"),
            "Proto_udt": int(proto == "udt")  #UDP-based Data Transfer Protocol
        }

        expected_states = ["OTH", "REJ", "RSTO", "RSTR", "RSTRH", "S0", "S1", "S2", "S3", "SF", "SH", "nan"]
        state_features = {f"State_{state}": int(conn_state == state) for state in expected_states}

        flags = reconstruct_flags(zeek, suri)

        features = {
            "Dur": duration,
            "TotPkts": tot_pkts,
            "TotBytes": tot_bytes,
            "SrcBytes": bytes_to,
            "DstBytes": bytes_from,
            "SrcPkts": pkts_to,
            "DstPkts": pkts_from,
            "Rate": rate,
            "SrcRate": src_rate,
            "DstRate": dst_rate,
            "Load": load,
            "SrcLoad": src_load,
            "DstLoad": dst_load,
            "sMeanPktSz": sMeanPktSz,
            "dMeanPktSz": dMeanPktSz,
            "ByteRatio": byte_ratio,
            "PktRatio": pkt_ratio,
            "PktsPerSec": pkts_per_sec,
            "BytesPerSec": bytes_per_sec,
        }

        features.update(flags)
        features.update(proto_features)
        features.update(state_features)

        missing = [f for f in input_features if f not in features]
        if missing:
            if DEBUG:
                print(f"[!] WARNING: Faltan features: {missing}")

        # Construir DataFrame asegurando orden correcto
        df = pd.DataFrame([[features.get(f, 0) for f in input_features]], columns=input_features)

        for col in df.columns:
            if col in numeric_real:
                df[col] = df[col].astype(np.float64)
            elif col.startswith("Proto_") or col.startswith("State_") or col.startswith("has_") or col == "is_unidirectional":
                df[col] = df[col].astype(np.int64)
            else:
                df[col] = df[col].astype(np.float64)

        if DEBUG:
            print("[DEBUG] Tipos por columna en combine_flows:")
            print(df.dtypes.value_counts())

        return df

    except Exception as e:
        print(f"[!] Error al combinar flujos: {e}")
        return None

def log_detection(flow, prediction):
    proto = flow.get("proto", "").lower()

    suricata_alert = flow.get("suri", {}).get("alert", None)
    suricata_alerts_list = flow.get("suri", {}).get("alerts", [])

    log = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": "ai_alert",
        "community_id": flow.get("community_id"),
        "src_ip": flow.get("zeek", {}).get("id.orig_h"),
        "src_port": flow.get("zeek", {}).get("id.orig_p"),
        "dst_ip": flow.get("zeek", {}).get("id.resp_h"),
        "dst_port": flow.get("zeek", {}).get("id.resp_p"),
        "proto": proto,
        "state": flow.get("conn_state", "unknown"),
        "prediction": prediction,
        "alert": {
            "signature": f"AI Detection: {prediction}",
            "category": "Deep Learning",
            "severity": 3
        },
        # Algunas métricas útiles
        "suricata_alert": suricata_alert,
        "Dur": flow.get("Dur", -1),
        "TotPkts": flow.get("TotPkts", -1),
        "TotBytes": flow.get("TotBytes", -1),
        "Flags": {k: flow.get(k, 0) for k in [
            'has_SYN', 'has_ACK', 'has_FIN', 'has_RST', 'has_PSH', 'has_URG', 'has_ECE', 'has_CWR']}
    }

    with open("/var/log/ai_ids.log", "a") as f:
        f.write(json.dumps(log) + "\n")


def is_background_system_traffic(flow):
    src = flow.get("src_ip", "")
    dst = flow.get("dest_ip", "")
    proto = flow.get("proto", "").lower()
    sport = int(flow.get("src_port", 0))
    dport = int(flow.get("dest_port", 0))
    tot_pkts = flow.get("TotPkts", 0)
    tot_bytes = flow.get("TotBytes", 0)
    dur = flow.get("Dur", 0.0)

    # Ignorar loopback y link-local
    if src.startswith("127.") or dst.startswith("127."):
        return True
    if src == "0.0.0.0" or src.startswith("169.254.") or dst.startswith("169.254."):
        return True
    if src.startswith("fe80::") or dst.startswith("ff02::"):
        return True

    # Tráfico UDP sospechoso y mínimo (probablemente broadcast del sistema)
    discovery_ports = {67, 68, 137, 138, 5353, 547}
    if proto == "udp" and (sport in discovery_ports or dport in discovery_ports):
        if tot_pkts <= 1 and tot_bytes < 300 and dur <= 0.01:
            return True

    # Broadcast UDP con un solo paquete
    if dst.endswith(".255") and proto == "udp":
        if tot_pkts <= 1 and tot_bytes < 300 and dur <= 0.01:
            return True

    return False

# Consumidor Kafka
consumer = KafkaConsumer(
    'zeek-flows', 'suricata-flows',
    bootstrap_servers='localhost:9092',
    value_deserializer=lambda m: json.loads(m.decode('utf-8')),
    auto_offset_reset='latest',
    enable_auto_commit=True,
    group_id='modelo-multifuente'
)

print("[+] Esperando flujos de Zeek y Suricata...")

cache = {}

for msg in consumer:
    topic = msg.topic
    flow = msg.value
    cid = flow.get("community_id")

    if topic == "zeek-flows":
        src_ip = flow.get("id.orig_h", "")
        dst_ip = flow.get("id.resp_h", "")
        dst_port = int(flow.get("id.resp_p", 0))

        if (src_ip != "10.1.1.10" and dst_ip != "10.1.1.10") or (dst_ip == "192.168.172.2" and dst_port == 53):
            continue

    if not cid:
        continue

    if cid not in cache:
        cache[cid] = {}

    cache[cid][topic] = flow

    if 'zeek-flows' in cache[cid] and 'suricata-flows' in cache[cid]:
        zeek = cache[cid]['zeek-flows']
        suri = cache[cid]['suricata-flows']

        if DEBUG:
            print("[*] Combinando flows...")
        x_df = combine_flows(zeek, suri)

        if x_df is None:
            del cache[cid]
            continue

        x_df = x_df[input_features]  # asegurar orden

        if DEBUG:
            print("[DEBUG] Tipos de columnas antes del pipeline:")
            print(x_df.dtypes.value_counts())

        src_ip = zeek.get("id.orig_h", "")
        src_port = zeek.get("id.orig_p", "")
        dst_ip = zeek.get("id.resp_h", "")
        dst_port = zeek.get("id.resp_p", "")

        enriched_flow = {
            "community_id": cid,
            "proto": zeek.get("proto", ""),
            "zeek": zeek,
            "suri": suri,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            **x_df.iloc[0].to_dict()
        }

        if is_background_system_traffic(enriched_flow):
            del cache[cid]
            continue

        # Imprimir las características del vector
        if DEBUG:
            print("[DEBUG] Características extraídas:")
            for feature, value in zip(input_features, x_df.values.flatten()):
                print(f"  {feature:>20}: {value}")

        x_scaled = preprocessing.transform(x_df)
        x_scaled = x_scaled.astype(np.float32)
        pred = model.predict(x_scaled)

        probs = dict(zip(label_encoder.classes_, pred[0].round(3)))
        pred_class = label_encoder.inverse_transform([np.argmax(pred)])[0]

        if DEBUG:
            print("[DEBUG] Probabilidades:", probs)

        print(f"[+] [{datetime.now().isoformat()}] | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Clase predicha: {pred_class}")

        log_detection(enriched_flow, pred_class)
        if pred_class == "scan":
            blockIP(src_ip, duration=300)

        del cache[cid]
