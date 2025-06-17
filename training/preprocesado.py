import os
import pandas as pd
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.utils import resample

os.environ['TCL_LIBRARY'] = 'C:/Users/34652/AppData/Local/Programs/Python/Python310/tcl/tcl8.6'
os.environ['TK_LIBRARY'] = 'C:/Users/34652/AppData/Local/Programs/Python/Python310/tcl/tk8.6'

# Carga y limpieza inicial
print("[+] Cargando dataset...")
df = pd.read_csv("datasetFinalBinario.csv", low_memory=False)
df["attack_type"] = df["attack_type"].replace("normal_scp", "normal_ssh")
df.dropna(subset=["SrcAddr", "DstAddr", "Sport", "Dport", "Proto"], inplace=True)

# Separación de tráfico normal y ataques
df_normal = df[df["label"] == 0].copy()
df_ataques = df[df["label"] != 0].copy()
df_ataques = df_ataques[df_ataques['Proto'].str.lower() != 'udp']

print("[+] Procesando ataques...")
subsets_ataques = []
max_samples = 700

# Estratificación de ataques (Flag_Combo -> Conn_State) para maximizar diversidad
for subtipo in df_ataques["attack_type"].unique():
    subset = df_ataques[df_ataques["attack_type"] == subtipo].copy()
    print(f"[*] {subtipo}: {len(subset)} flujos antes del muestreo")

    subset["conn_state"] = subset["conn_state"].fillna("NONE").astype(str)
    subset["history"] = subset["history"].fillna("").str.upper()
    subset["flag_combo"] = subset["history"].apply(lambda h: "".join(sorted(set(h))))

    if len(subset) >= 10:
        print(f"[>] Estratificando {subtipo} por flag_combo → conn_state")
        estratificados = []

        flag_combo_counts = subset["flag_combo"].value_counts(normalize=True)

        for flag_combo, grupo_flags in subset.groupby("flag_combo"):
            n_flag = int(round(flag_combo_counts[flag_combo] * max_samples))
            if n_flag < 3 or len(grupo_flags) < 3:
                continue

            cs_counts = grupo_flags["conn_state"].value_counts(normalize=True)
            for cs, grupo_cs in grupo_flags.groupby("conn_state"):
                n_cs = int(round(cs_counts[cs] * n_flag))
                
                if cs == "SF":
                    n_cs = max(n_cs, 200)
                
                if n_cs < 1:
                    continue

                sampled = (grupo_cs.sample(n=n_cs, random_state=42)
                           if len(grupo_cs) >= n_cs
                           else resample(grupo_cs, n_samples=n_cs, replace=True, random_state=42))
                estratificados.append(sampled)

        if estratificados:
            subset = pd.concat(estratificados, ignore_index=True)
        else:
            print(f"[!] Estratificación fallida para {subtipo}, muestreo simple")
            subset = resample(subset, n_samples=max_samples, replace=True, random_state=42)

    else:
        print(f"[!] {subtipo} tiene muy pocos flujos, muestreo con reemplazo")
        subset = resample(subset, n_samples=max_samples, replace=True, random_state=42)

    # Quitar duplicados post-estratificación
    subset = subset.drop_duplicates(subset=["SrcAddr", "DstAddr", "Sport", "Dport", "Dur", "TotBytes"])
    subsets_ataques.append(subset)

all_attacks = pd.concat(subsets_ataques, ignore_index=True)
all_attacks = all_attacks.drop_duplicates(subset=["SrcAddr", "DstAddr", "Sport", "Dport", "Dur", "TotBytes"])

for subtipo in all_attacks["attack_type"].unique():
    sub = all_attacks[all_attacks["attack_type"] == subtipo]
    print(f"{subtipo} ({len(sub)})")
    print(sub.groupby(["flag_combo", "conn_state"]).size().reset_index(name="count"))
    print()

print("[+] Procesando tráfico normal de manera proporcional...")
target_normal = 6000
normal_counts = df_normal["attack_type"].value_counts(normalize=True)
subsets_normal = []

# Muestreo proporcional del tráfico normal
for subtipo, proporcion in normal_counts.items():
    n_subtipo = int(round(proporcion * target_normal))
    subset = df_normal[df_normal["attack_type"] == subtipo]
    
    if len(subset) > n_subtipo:
        sampled = subset.sample(n=n_subtipo, random_state=42)
    else:
        sampled = subset.copy()  # no resample para mantener la naturalidad
    subsets_normal.append(sampled)

all_attacks = pd.concat(subsets_ataques, ignore_index=True)
all_normal = pd.concat(subsets_normal, ignore_index=True)
df_final = pd.concat([all_attacks, all_normal], ignore_index=True)

# Features derivadas

# Flags TCP
if "history" in df_final.columns:
    df_final["history"] = df_final["history"].fillna("").str.upper()
    for flag in ["S", "R", "F", "A", "P", "U", "E", "C"]:
        name = {"S": "SYN", "R": "RST", "F": "FIN", "A": "ACK", "P": "PSH", "U": "URG", "E": "ECE", "C": "CWR"}[flag]
        df_final[f"has_{name}"] = df_final["history"].str.contains(flag).astype(int)
else:
    print("[!] 'history' no existe -> No se pueden calcular las flags TCP")

df_final["ByteRatio"] = np.where(df_final["DstBytes"] > 0, df_final["SrcBytes"] / df_final["DstBytes"], 0)
df_final["PktRatio"] = np.where(df_final["DstPkts"] > 0, df_final["SrcPkts"] / df_final["DstPkts"], 0)
df_final["SrcRate"] = np.where(df_final["Dur"] > 0, df_final["SrcBytes"] / df_final["Dur"], 0)
df_final["DstRate"] = np.where(df_final["Dur"] > 0, df_final["DstBytes"] / df_final["Dur"], 0)
df_final["SrcLoad"] = np.where(df_final["Dur"] > 0, df_final["SrcRate"] / df_final["Dur"], 0)
df_final["PktsPerSec"] = np.where(df_final["Dur"] > 0, df_final["TotPkts"] / df_final["Dur"], 0)
df_final["BytesPerSec"] = np.where(df_final["Dur"] > 0, df_final["TotBytes"] / df_final["Dur"], 0)
df_final["Proto"] = df_final["Proto"].astype(str)
df_final["conn_state"] = df_final["conn_state"].astype(str)

df_final.drop(columns=["history", "label", "flag_combo"], errors="ignore", inplace=True)

# One-hot encoding
df_final = pd.get_dummies(df_final, columns=["Proto", "conn_state"], prefix=["Proto", "State"])

print(f"[+] Dataset final generado con {len(df_final)} flujos")
df_final.to_csv("datasetFinal.csv", index=False)
print("[+] Guardado como datasetFinal.csv")


# Estadísticas y visualizaciones
print("\n[+] Ataques por subtipo:")
print(all_attacks["attack_type"].value_counts())

print("\n[+] Normales por subtipo:")
print(all_normal["attack_type"].value_counts())

print("\n[+] Resumen por subtipo y conn_state:")
for subtipo in all_attacks["attack_type"].unique():
    sub = all_attacks[all_attacks["attack_type"] == subtipo]
    print(f"{subtipo} ({len(sub)})")
    print(sub["conn_state"].value_counts())
    print()

label_colors = {
    0: "#C7CD83",  # Normal
    1: "#483E46"   # Ataque
}

category_colors = {
    "normal": "#C7CD83",
    "dos": "#7E7A88",
    "brute": "#483E46",
    "scan": "#31282D"
}

ataques = all_attacks["attack_type"].value_counts().to_dict()
normales = all_normal["attack_type"].value_counts().to_dict()

df_ataques = pd.DataFrame(list(ataques.items()), columns=["subtipo", "count"])
df_ataques["label"] = 1
df_ataques["attack_category"] = "scan"  # si añades 'brute' o 'dos', deberías ajustarlo dinámicamente

df_normales = pd.DataFrame(list(normales.items()), columns=["subtipo", "count"])
df_normales["label"] = 0
df_normales["attack_category"] = "normal"

df_final = pd.concat([df_ataques, df_normales], ignore_index=True)

label_totals = df_final.groupby("label")["count"].sum()
label_names = ["Normal", "Ataque"]
label_colors_plot = [label_colors[0], label_colors[1]]

plt.figure(figsize=(6, 4))
plt.bar(label_names, label_totals, color=label_colors_plot)
plt.title("Distribución general por clase")
plt.ylabel("Cantidad de flujos")
plt.tight_layout()
plt.show()

plt.figure(figsize=(10, 5))
for category in df_final["attack_category"].unique():
    subset = df_final[df_final["attack_category"] == category]
    plt.bar(subset["subtipo"], subset["count"], label=category, color=category_colors[category])

plt.title("Distribución por subtipo y categoría")
plt.ylabel("Cantidad de flujos")
plt.xticks(rotation=45, ha="right")
plt.legend(title="Categoría")
plt.tight_layout()
plt.show()

for subtipo in all_attacks["attack_type"].unique():
    sub = all_attacks[all_attacks["attack_type"] == subtipo]
    counts = sub.groupby(["flag_combo", "conn_state"]).size().reset_index(name="count")

    plt.figure(figsize=(10, 6))
    pivot = counts.pivot(index="flag_combo", columns="conn_state", values="count").fillna(0)
    sns.heatmap(pivot, annot=True, fmt=".0f", cmap="Blues")
    plt.title(f"Distribución de {subtipo}")
    plt.xlabel("conn_state")
    plt.ylabel("flag_combo")
    plt.tight_layout()
    plt.show()