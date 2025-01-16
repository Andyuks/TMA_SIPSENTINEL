import pyshark
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

#-----------------------------------------------------------
# GESTIONAR DATOS
# Leer los paquetes de un archivo PCAP
def extract_features(pcap_file):
    cap = pyshark.FileCapture(pcap_file)
    features = []

    for pkt in cap:
        try:
            features.append({
                'packet_size': int(pkt.length),
                'protocol': pkt.highest_layer,
                'src_port': int(pkt[pkt.transport_layer].srcport) if pkt.transport_layer else 0,
                'dst_port': int(pkt[pkt.transport_layer].dstport) if pkt.transport_layer else 0,
                'time': float(pkt.sniff_timestamp),
                'sip_status': pkt.sip.Status_Code if 'SIP' in pkt else None,
                'rtp_payload_type': pkt.rtp.payload_type if 'RTP' in pkt else None
            })
        except AttributeError:
            continue

    cap.close()
    return pd.DataFrame(features)

def prepare_dataset(pcap_files, labels):
    df_list = []
    for pcap_file, label in zip(pcap_files, labels):
        df = extract_features(pcap_file)
        df['label'] = label
        df_list.append(df)

    return pd.concat(df_list, ignore_index=True)

#-----------------------------------------------------------
# Configuración de datos y etiquetas
pcap_files = ['trafico_sip.pcap', 'SPIT_A_Host_Client4.pcap']
labels = ['normal', 'ataque']  # Etiquetas correspondientes a los PCAPs

# Cargar las características desde los archivos PCAP
dataset = prepare_dataset(pcap_files, labels)

# Verificar las primeras filas del dataset
print("Primeras filas del dataset:")
print(dataset.head())

#-----------------------------------------------------------
# Preprocesar datos
# Llenar valores nulos en las columnas con 0 o valores predeterminados
dataset.fillna({'sip_status': 0, 'rtp_payload_type': 0}, inplace=True)

# Convertir las columnas categóricas a variables numéricas
dataset = pd.get_dummies(dataset, columns=['protocol'])

# Separar las características (X) y las etiquetas (y)
X = dataset.drop(columns=["label"])
y = dataset["label"]

# Dividir los datos en entrenamiento y prueba (80% - 20%)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

#-----------------------------------------------------------
# MODELO
# Crear el modelo de Random Forest
model = RandomForestClassifier(random_state=42)

# Entrenar el modelo
model.fit(X_train, y_train)

# Hacer predicciones
y_pred = model.predict(X_test)

# Evaluar el modelo
accuracy = accuracy_score(y_test, y_pred)
print(f"\nPrecisión del modelo: {accuracy * 100:.2f}%")

# Informe de clasificación
print("\nInforme de Clasificación:")
print(classification_report(y_test, y_pred))

#-----------------------------------------------------------
# Matriz de confusión
# Clases que se van a predecir
labels = ['normal', 'ataque']

# Calcular matriz de confusión
cm = confusion_matrix(y_test, y_pred, labels=labels)
print("\nMatriz de Confusión:")
print(cm)

# Visualizar la matriz de confusión
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=labels, yticklabels=labels)
plt.title("Matriz de Confusión")
plt.xlabel("Predicción")
plt.ylabel("Real")
plt.show()

