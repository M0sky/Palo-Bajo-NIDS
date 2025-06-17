import os
import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import datetime
import joblib
import pickle

from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline

import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization, LeakyReLU, Input
from tensorflow.keras.utils import to_categorical
from tensorflow.keras.callbacks import EarlyStopping, TensorBoard, ReduceLROnPlateau
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.regularizers import l2

# config
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
os.environ['TCL_LIBRARY'] = 'C:/Users/34652/AppData/Local/Programs/Python/Python310/tcl/tcl8.6'
os.environ['TK_LIBRARY'] = 'C:/Users/34652/AppData/Local/Programs/Python/Python310/tcl/tk8.6'

# Carga
dataset_path = "datasetFinal.csv"
log_dir = "logs/fit/" + datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
os.makedirs(log_dir, exist_ok=True)

df = pd.read_csv(dataset_path)
df.columns = df.columns.str.strip()
df["attack_category"] = df["attack_category"].fillna("unknown")

# Objetivo -> attack_category
drop_cols = ["attack_category", "attack_type", "SrcAddr", "DstAddr", "Sport", "Dport", "State"]
X = df.drop(columns=drop_cols, errors="ignore")
y = df["attack_category"]

label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)
num_classes = len(label_encoder.classes_)
y_categorical = to_categorical(y_encoded, num_classes=num_classes)

print("\n[DEBUG] Columnas con NaN:")
print(X.isnull().sum()[X.isnull().sum() > 0])

joblib.dump(X.columns.tolist(), "input_features_FINAL.pkl")
assert not X.isnull().any().any(), "X contiene NaN"

input_features = X.columns.tolist()

# Features numéricas reales para el escalado
numeric_real = [
    'Dur', 'TotPkts', 'TotBytes', 'SrcBytes', 'DstBytes',
    'SrcPkts', 'DstPkts', 'Rate', 'SrcRate', 'DstRate',
    'Load', 'SrcLoad', 'DstLoad',
    'sMeanPktSz', 'dMeanPktSz',
    'PktSizeVar', 'error_ratio', 'ByteRatio', 'PktRatio',
    'PktsPerSec', 'BytesPerSec', 'MeanPktSize',
    'SrcBytes_per_SrcPkt', 'DstBytes_per_DstPkt',
    'DstBytes_per_SrcPkt', 'SrcBytes_per_DstPkt',
    'ByteRatioPktAdj', 'AbsByteDiff', 'AbsPktDiff'
]

# Asegurar que las columnas existen
numeric_real = [col for col in numeric_real if col in X.columns]
flags = ['has_FIN', 'has_SYN', 'has_RST', 'has_PSH', 'has_ACK', 'has_URG', 'has_ECE', 'has_CWR']
flags = [col for col in flags if col in X.columns]
categorical = [col for col in X.columns if col not in numeric_real + flags]

with open("numeric_features_FINAL.pkl", "wb") as f:
    pickle.dump(numeric_real, f)

# ColumnTransformer separado por tipo
preprocessor = ColumnTransformer(
    transformers=[
        ("num", Pipeline([
            ("imputer", SimpleImputer(missing_values=-1, strategy="mean")),
            ("scaler", StandardScaler())
        ]), numeric_real),
        ("flags", "passthrough", flags),
        ("cat", "passthrough", categorical)
    ]
)

# Validación cruzada
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
fold = 1
histories = []

for train_index, test_index in skf.split(X, y_encoded):
    print(f"\n[+] Fold {fold}")
    X_train, X_test = X.iloc[train_index], X.iloc[test_index]
    y_train_raw, y_test_raw = y_encoded[train_index], y_encoded[test_index]

    y_train = to_categorical(y_train_raw, num_classes=num_classes)
    y_test = to_categorical(y_test_raw, num_classes=num_classes)

    preprocessing_pipeline = Pipeline(steps=[("preprocessor", preprocessor)])

    X_train_scaled = preprocessing_pipeline.fit_transform(X_train).astype(np.float32)
    X_test_scaled = preprocessing_pipeline.transform(X_test).astype(np.float32)

    model = Sequential([
        Input(shape=(X_train_scaled.shape[1],)),
        Dense(128, kernel_regularizer=l2(0.001)),
        BatchNormalization(),
        LeakyReLU(),
        Dropout(0.2),

        Dense(64, kernel_regularizer=l2(0.001)),
        BatchNormalization(),
        LeakyReLU(),
        Dropout(0.1),

        Dense(num_classes, activation="softmax")
    ])

    model.compile(optimizer=Adam(0.001), loss="categorical_crossentropy", metrics=["accuracy"])

    callbacks = [
        EarlyStopping(monitor="val_loss", patience=10, restore_best_weights=True),
        ReduceLROnPlateau(monitor="val_loss", factor=0.5, patience=5),
        TensorBoard(log_dir=os.path.join(log_dir, f"fold_{fold}"))
    ]

    history = model.fit(
        X_train_scaled, y_train,
        validation_data=(X_test_scaled, y_test),
        epochs=150, batch_size=64,
        callbacks=callbacks, verbose=1
    )
    histories.append(history)

    y_pred = np.argmax(model.predict(X_test_scaled), axis=1)
    y_true = np.argmax(y_test, axis=1)

    print(classification_report(y_true, y_pred, target_names=label_encoder.classes_))

    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(10, 7))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=label_encoder.classes_, yticklabels=label_encoder.classes_)
    plt.title(f"Matriz de Confusión - Fold {fold}")
    plt.xlabel("Predicción")
    plt.ylabel("Real")
    plt.tight_layout()
    plt.savefig(f"confusion_matrix_fold{fold}.png")
    plt.close()

    fold += 1

# Curvas de entrenamiento por fold
for i, history in enumerate(histories, 1):
    plt.figure(figsize=(12, 5))
    plt.subplot(1, 2, 1)
    plt.plot(history.history["loss"], label="Train")
    plt.plot(history.history["val_loss"], label="Val")
    plt.title(f"Fold {i} - Loss")
    plt.legend()
    plt.subplot(1, 2, 2)
    plt.plot(history.history["accuracy"], label="Train")
    plt.plot(history.history["val_accuracy"], label="Val")
    plt.title(f"Fold {i} - Accuracy")
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"training_curves_fold{i}.png")
    plt.close()


# Entrenamiento final
print("[+] Entrenamiento final (90% train / 10% val)")

# Dividir el dataset
from sklearn.model_selection import train_test_split

X_final = df.drop(columns=drop_cols, errors="ignore")
y_final = df["attack_category"]

X_train, X_val, y_train, y_val = train_test_split(
    X_final, y_final, test_size=0.1, stratify=y_final, random_state=42
)

# Codificación de etiquetas
y_train_encoded = label_encoder.transform(y_train)
y_val_encoded = label_encoder.transform(y_val)

y_train_cat = to_categorical(y_train_encoded, num_classes=num_classes)
y_val_cat = to_categorical(y_val_encoded, num_classes=num_classes)

print("\n[DEBUG] Tipos de columnas en X_train antes del pipeline:")
print(X_train.dtypes.value_counts())

print("\n[DEBUG] Tipos de columnas detallados:")
print(X_train.dtypes.sort_index())

pipeline = Pipeline(steps=[("preprocessor", preprocessor)])
X_train_scaled = pipeline.fit_transform(X_train).astype(np.float32)
X_val_scaled = pipeline.transform(X_val).astype(np.float32)

final_model = Sequential([
    Input(shape=(X_train_scaled.shape[1],)),
    Dense(128, kernel_regularizer=l2(0.001)),
    BatchNormalization(),
    LeakyReLU(),
    Dropout(0.2),

    Dense(64, kernel_regularizer=l2(0.001)),
    BatchNormalization(),
    LeakyReLU(),
    Dropout(0.1),

    Dense(num_classes, activation="softmax")
])

final_model.compile(optimizer=Adam(0.001), loss="categorical_crossentropy", metrics=["accuracy"])

final_model.fit(
    X_train_scaled, y_train_cat,
    validation_data=(X_val_scaled, y_val_cat),
    epochs=100, batch_size=64,
    callbacks=[
        EarlyStopping(monitor="val_loss", patience=10, restore_best_weights=True),
        ReduceLROnPlateau(monitor="val_loss", factor=0.5, patience=5)
    ],
    verbose=1
)

# Evaluación final
y_pred_final = np.argmax(final_model.predict(X_val_scaled), axis=1)
y_true_final = np.argmax(y_val_cat, axis=1)

print("\n[+] Reporte final:")
print(classification_report(y_true_final, y_pred_final, target_names=label_encoder.classes_))

print("\n[+] Sumario:")
final_model.summary()

cm = confusion_matrix(y_true_final, y_pred_final)
plt.figure(figsize=(10, 7))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=label_encoder.classes_,
            yticklabels=label_encoder.classes_)
plt.title("Matriz de Confusión - Modelo Final")
plt.tight_layout()
plt.savefig("confusion_matrix_final.png")
plt.show()

# Guardado
final_model.save("modelo_FINAL.keras")
joblib.dump(pipeline, "preprocessing_pipeline_FINAL.pkl")
joblib.dump(label_encoder, "label_encoder_FINAL.pkl")
print("[+] Modelo y recursos guardados correctamente.")

# Nombres de columnas transformadas después del pipeline
def get_feature_names_from_column_transformer(ct):
    output_features = []

    for name, trans, cols in ct.transformers_:
        if name == 'remainder' and trans == 'drop':
            continue
        if hasattr(trans, 'get_feature_names_out'):
            try:
                feature_names = trans.get_feature_names_out(cols)
            except:
                feature_names = cols  # fallback
        else:
            feature_names = cols
        output_features.extend(feature_names)
    return output_features

feature_names = get_feature_names_from_column_transformer(pipeline.named_steps["preprocessor"])

# Extraer la primera capa densa
first_layer_weights = final_model.layers[0].get_weights()[0]  # Matriz (n_features, n_neuronas)

# Calcular la importancia
importancia = np.sum(np.abs(first_layer_weights), axis=1)  # Vector (n_features,)

# Asociar con los nombres de columnas
feature_importance = pd.DataFrame({
    "Feature": feature_names,
    "Importance": importancia
}).sort_values("Importance", ascending=False)

print(feature_importance)
df_sorted = feature_importance.sort_values(by="Importance", ascending=True)

plt.figure(figsize=(10, 8))
sns.barplot(x="Importance", y="Feature", data=df_sorted, palette="magma")
plt.title("Importancia de características (pesos primera capa)", fontsize=14)
plt.xlabel("Importancia (suma de pesos absolutos)")
plt.ylabel("Característica")
plt.grid(axis='x', linestyle='--', alpha=0.4)
plt.tight_layout()
plt.gca().invert_yaxis()
plt.show()