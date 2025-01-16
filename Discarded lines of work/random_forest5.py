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
def extract_pcap_features(pcap_file):
    cap = pyshark.FileCapture(pcap_file)

    data = []
    sip_invites = {}  # Diccionario para contar INVITES por destino
    rtp_packets = 0  # Contador de paquetes RTP para detección de RTP flooding
    start_time = None  # Tiempo de inicio para detectar intervalos
    last_timestamp = None  # Variable para almacenar el último timestamp

    for packet in cap:
        features = {
            "timestamp": float(packet.sniff_time.timestamp()),
            "length": int(packet.length),
        }

        # Detectar el tipo de protocolo IP (IPv4 o IPv6)
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            features["src_ip"] = src_ip
            features["dst_ip"] = dst_ip
        elif hasattr(packet, 'ipv6'):
            src_ip = packet.ipv6.src
            dst_ip = packet.ipv6.dst
            features["src_ip"] = src_ip
            features["dst_ip"] = dst_ip
        else:
            features["src_ip"] = 'N/A'
            features["dst_ip"] = 'N/A'

        # Inicializar el valor del protocolo
        features["protocol"] = 'N/A'

        # Identificar protocolo de transporte (TCP o UDP)
        if hasattr(packet, 'tcp'):
            features["protocol"] = 'TCP'
            features["src_port"] = int(packet.tcp.srcport)
            features["dst_port"] = int(packet.tcp.dstport)
            
            # Verificar si es SIP en TCP (puerto 5060)
            if features["src_port"] == 5060 or features["dst_port"] == 5060:
                features["protocol"] = 'SIP'  # Marcar como SIP si se usa puerto 5060
        elif hasattr(packet, 'udp'):
            features["protocol"] = 'UDP'
            features["src_port"] = int(packet.udp.srcport)
            features["dst_port"] = int(packet.udp.dstport)
            
            # Verificar si es SIP en UDP (puerto 5060)
            if features["src_port"] == 5060 or features["dst_port"] == 5060:
                features["protocol"] = 'SIP'  # Marcar como SIP si se usa puerto 5060
                
            # Verificar si es RTP (puertos 10000-20000)
            if 10000 <= features["src_port"] <= 20000 or 10000 <= features["dst_port"] <= 20000 or features["src_port"] == 8000 or features["dst_port"] == 8000:
                features["protocol"] = 'RTP'  # Marcar como RTP si se usa un puerto entre 10000 y 20000 y el puerto 8000
        elif hasattr(packet, 'icmp'):
            features["protocol"] = 'ICMP'
            features["src_port"] = -1  # ICMP no tiene puertos
            features["dst_port"] = -1  # ICMP no tiene puertos
        else:
            features["src_port"] = -1
            features["dst_port"] = -1

        # Verificar el intervalo de tiempo entre paquetes
        current_timestamp = float(packet.sniff_time.timestamp())
        
        if last_timestamp is not None:
            interval = current_timestamp - last_timestamp
        else:
            interval = 0  # El primer paquete no tiene un intervalo previo

        # Detectar ataques SIP o RTP según el intervalo de tiempo
        if interval <= 1:  # Si el intervalo entre paquetes es menor o igual a 1 segundo
            if features["protocol"] == "SIP":
                # Contabilizar INVITES por destino
                if features["dst_ip"] not in sip_invites:
                    sip_invites[features["dst_ip"]] = 0
                sip_invites[features["dst_ip"]] += 1
            elif features["protocol"] == "RTP":
                rtp_packets += 1
        else:
            # Si el intervalo de tiempo es mayor a 1 segundo, reiniciar los contadores
            sip_invites = {}
            rtp_packets = 0

        # Etiquetado de ataques
        ataque_detectado = False
        # Revisa si hay más de 10 SIP INVITES a un mismo destino
        for dst, count in sip_invites.items():
            if count > 10:  # Umbral de ataque SIP
                features["Etiqueta"] = 'ataque_SIP'
                ataque_detectado = True
                break
        
        if not ataque_detectado:
            if rtp_packets > 100:  # Si hay más de 100 paquetes RTP en un intervalo de 1 segundo
                features["Etiqueta"] = 'ataque_RTP'
            else:
                features["Etiqueta"] = 'normal'

        # Agregar el paquete a la lista de datos
        data.append(features)

        # Actualizar el timestamp del último paquete
        last_timestamp = current_timestamp

    return pd.DataFrame(data)

# Cargar las características desde el archivo PCAP
data = extract_pcap_features('trafico_sip.pcap')

# Comprobamos las primeras filas
print(data)

# Convertir las columnas categóricas a variables numéricas
data = pd.get_dummies(data, columns=["protocol", "src_ip", "dst_ip"])

# Separar las características (X) y las etiquetas (y)
X = data.drop(columns=["Etiqueta"])
y = data["Etiqueta"]

# Dividir los datos en entrenamiento y prueba (80% - 20%)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

#-----------------------------------------------------------
# MODELO
# Crear el modelo de Random Forest
model = RandomForestClassifier(n_estimators=100, random_state=42)

# Entrenar el modelo
model.fit(X_train, y_train)

# Hacer predicciones
y_pred = model.predict(X_test)

# Evaluar el modelo
accuracy = accuracy_score(y_test, y_pred)
print(f"Precisión del modelo: {accuracy * 100:.2f}%")

# Informe de clasificación
print("\nInforme de Clasificación:")
print(classification_report(y_test, y_pred))  # Matriz de Confusión
print("\nMatriz de Confusión:")

# Asegurarse de especificar las clases en la matriz de confusión
labels = ['normal', 'ataque_SIP', 'ataque_RTP']  # Clases que se van a predecir
cm = confusion_matrix(y_test, y_pred, labels=labels)
print(cm)

#---------------------------------
# VISUALIZACION
# Visualizar la matriz de confusión
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=labels, yticklabels=labels)
plt.title("Matriz de Confusión")
plt.xlabel("Predicción")
plt.ylabel("Real")
plt.show()

