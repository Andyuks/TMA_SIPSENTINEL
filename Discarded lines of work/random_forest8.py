import pyshark
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import time

#-----------------------------------------------------------
# FEATURE EXTRACTION
def extract_features(pcap_file):
    cap = pyshark.FileCapture(pcap_file)
    features = []

    for pkt in cap:
        try:
            # Packet-level features
            packet_size = int(pkt.length)
            protocol = pkt.highest_layer
            src_port = int(pkt[pkt.transport_layer].srcport) if pkt.transport_layer else 0
            dst_port = int(pkt[pkt.transport_layer].dstport) if pkt.transport_layer else 0
            time_stamp = float(pkt.sniff_timestamp)

            # SIP-specific features
            sip_status = pkt.sip.Status_Code if 'SIP' in pkt else None
            method = pkt.sip.Method if 'SIP' in pkt else None

            # RTP-specific features
            rtp_payload_type = pkt.rtp.payload_type if 'RTP' in pkt else None

            features.append({
                'packet_size': packet_size,
                'protocol': protocol,
                'src_port': src_port,
                'dst_port': dst_port,
                'time': time_stamp,
                'sip_status': sip_status,
                'sip_method': method,
                'rtp_payload_type': rtp_payload_type
            })
        except AttributeError:
            continue

    cap.close()
    return pd.DataFrame(features)

# Prepare the dataset with features
def prepare_dataset(pcap_files, labels):
    df_list = []
    for pcap_file, label in zip(pcap_files, labels):
        df = extract_features(pcap_file)
        df['label'] = label
        df_list.append(df)

    dataset = pd.concat(df_list, ignore_index=True)

    # Add traffic metrics
    dataset['inter_packet_time'] = dataset['time'].diff().fillna(0)
    source_stats = dataset.groupby('src_port')['packet_size'].agg(['count', 'mean'])
    dataset['src_packet_count'] = dataset['src_port'].map(source_stats['count'])
    dataset['src_packet_mean_size'] = dataset['src_port'].map(source_stats['mean'])

    return dataset

# Extract features from live traffic
def extract_live_traffic(interface, duration):
    cap = pyshark.LiveCapture(interface=interface)
    cap.sniff(timeout=duration)
    features = []

    for pkt in cap:
        try:
            # Packet-level features
            packet_size = int(pkt.length)
            protocol = pkt.highest_layer
            src_port = int(pkt[pkt.transport_layer].srcport) if pkt.transport_layer else 0
            dst_port = int(pkt[pkt.transport_layer].dstport) if pkt.transport_layer else 0
            time_stamp = float(pkt.sniff_timestamp)

            # SIP-specific features
            sip_status = pkt.sip.Status_Code if 'SIP' in pkt else None
            method = pkt.sip.Method if 'SIP' in pkt else None

            # RTP-specific features
            rtp_payload_type = pkt.rtp.payload_type if 'RTP' in pkt else None

            features.append({
                'packet_size': packet_size,
                'protocol': protocol,
                'src_port': src_port,
                'dst_port': dst_port,
                'time': time_stamp,
                'sip_status': sip_status,
                'sip_method': method,
                'rtp_payload_type': rtp_payload_type
            })
        except AttributeError:
            continue

    cap.close()
    df = pd.DataFrame(features)
    if not df.empty:
        df['inter_packet_time'] = df['time'].diff().fillna(0)
        source_stats = df.groupby('src_port')['packet_size'].agg(['count', 'mean'])
        df['src_packet_count'] = df['src_port'].map(source_stats['count'])
        df['src_packet_mean_size'] = df['src_port'].map(source_stats['mean'])
    return df

#-----------------------------------------------------------
# CONFIGURATION
pcap_files = [
    "nonvpn_voip_capture1.pcap",
    "nonvpn_voip_capture2.pcap",
    "nonvpn_voip_capture3.pcap",
    "RTP Flood/RTP_A_Host_Asterisk_IP-PBX.pcap",
    "RTP Flood/RTP_A_Host_Attacker.pcap",
    "RTP Flood/RTP_A_Host_Client1.pcap",
    "RTP Flood/RTP_A_Host_Client2.pcap",
    "RTP Flood/RTP_A_Host_Client3.pcap",
    "RTP Flood/RTP_A_Host_Client4.pcap",
    "RTP Flood/RTP_B_Host_Asterisk_IP-PBX.pcap",
    "RTP Flood/RTP_B_Host_Attacker.pcap",
    "RTP Flood/RTP_B_Host_Client1.pcap",
    "RTP Flood/RTP_B_Host_Client2.pcap",
    "RTP Flood/RTP_B_Host_Client3.pcap",
    "RTP Flood/RTP_B_Host_Client4.pcap",
    "Sipsak/Sipsak_A_Host_Asterisk_IP-PBX.pcap",
    "Sipsak/Sipsak_A_Host_Attacker.pcap",
    "Sipsak/Sipsak_A_Host_Client1.pcap",
    "Sipsak/Sipsak_A_Host_Client2.pcap",
    "Sipsak/Sipsak_A_Host_Client3.pcap",
    "Sipsak/Sipsak_A_Host_Client4.pcap",
    "SPIT-spam/Spit_A_Host_Asterisk_IP-PBX.pcap",
    "SPIT-spam/Spit_A_Host_Attacker.pcap",
    "SPIT-spam/Spit_A_Host_Client1.pcap",
    "SPIT-spam/Spit_A_Host_Client2.pcap",
    "SPIT-spam/Spit_A_Host_Client3.pcap",
    "SPIT-spam/Spit_A_Host_Client4.pcap",
    "Invite Flood/Invite_A_Host_Asterisk_IP-PBX.pcap",
    "Invite Flood/Invite_A_Host_Attacker.pcap",
    "Invite Flood/Invite_A_Host_Client1.pcap",
    "Invite Flood/Invite_A_Host_Client2.pcap",
    "Invite Flood/Invite_A_Host_Client3.pcap",
    "Invite Flood/Invite_A_Host_Client4.pcap",
    "Invite Flood/Invite_B_Host_Asterisk_IP-PBX.pcap",
    "Invite Flood/Invite_B_Host_Attacker.pcap",
    "Invite Flood/Invite_B_Host_Client1.pcap",
    "Invite Flood/Invite_B_Host_Client2.pcap",
    "Invite Flood/Invite_B_Host_Client3.pcap",
    "Invite Flood/Invite_B_Host_Client4.pcap",
    "BYE/Teardown_A_Host_Asterisk_IP-PBX.pcap",
    "BYE/Teardown_A_Host_Attacker.pcap",
    "BYE/Teardown_A_Host_Client1.pcap",
    "BYE/Teardown_A_Host_Client2.pcap",
    "BYE/Teardown_A_Host_Client3.pcap",
    "BYE/Teardown_A_Host_Client4.pcap",
    "BYE/Teardown_B_Host_Asterisk_IP-PBX.pcap",
    "BYE/Teardown_B_Host_Attacker.pcap",
    "BYE/Teardown_B_Host_Client1.pcap",
    "BYE/Teardown_B_Host_Client2.pcap",
    "BYE/Teardown_B_Host_Client3.pcap",
    "BYE/Teardown_B_Host_Client4.pcap",
    "BYE/Register Hijacking/Reghijack_A_Host_Asterisk_IP-PBX.pcap",
    "BYE/Register Hijacking/Reghijack_A_Host_Attacker.pcap",
    "BYE/Register Hijacking/Reghijack_A_Host_Client1.pcap",
    "BYE/Register Hijacking/Reghijack_A_Host_Client2.pcap",
    "BYE/Register Hijacking/Reghijack_A_Host_Client3.pcap",
    "BYE/Register Hijacking/Reghijack_A_Host_Client4.pcap",
    "BYE/Register Hijacking/Reghijack_B_Host_Asterisk_IP-PBX.pcap",
    "BYE/Register Hijacking/Reghijack_B_Host_Attacker.pcap",
    "BYE/Register Hijacking/Reghijack_B_Host_Client1.pcap",
    "BYE/Register Hijacking/Reghijack_B_Host_Client2.pcap",
    "BYE/Register Hijacking/Reghijack_B_Host_Client3.pcap",
    "BYE/Register Hijacking/Reghijack_B_Host_Client4.pcap"
]
labels = ['normal',
    'normal',
    'normal',
    'normal',
    'attack',
    'attack',
    'normal',
    'normal',
    'normal',
    'normal',
    'attack',
    'attack',
    'normal',
    'normal',
    'normal',
    'normal',
    'attack',
    'attack',
    'normal',
    'normal',
    'normal',
    'normal',
    'attack',
    'attack',
    'normal',
    'normal',
    'normal',
    'normal',
    'attack',
    'attack',
    'normal',
    'normal',
    'normal',
    'normal',
    'attack',
    'attack',
    'normal',
    'normal',
    'normal',
    'normal',
    'attack',
    'attack',
    'normal',
    'normal',
    'normal',
    'normal',
    'attack',
    'attack',
    'normal',
    'normal',
    'normal',
    'normal']

#-----------------------------------------------------------
# MAIN FUNCTION

def main():
    print("Select an option:")
    print("0 - Train and save model")
    print("1 - Analyze a PCAP file using the saved model")
    print("2 - Analyze live traffic using the saved model")

    choice = int(input("Enter your choice: "))

    if choice == 0:
        print("Training and saving the model...")
        dataset = prepare_dataset(pcap_files, labels)
        dataset.fillna({'sip_status': 0, 'rtp_payload_type': 0, 'sip_method': 'UNKNOWN'}, inplace=True)
        dataset = pd.get_dummies(dataset, columns=['protocol', 'sip_method'])

        X = dataset.drop(columns=['label', 'time'])
        y = dataset['label']
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        model = RandomForestClassifier(random_state=42)
        model.fit(X_train, y_train)

        print("Model trained. Saving the model...")
        joblib.dump(model, 'sip_anomaly_model.pkl')
        print("Model saved as 'sip_anomaly_model.pkl'.")

        # Predictions and Evaluation
        y_pred = model.predict(X_test)
        print("\nEvaluation on Test Data:")
        print(f"Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))

        print("\nConfusion Matrix:")
        cm = confusion_matrix(y_test, y_pred, labels=['normal', 'attack'])
        print(cm)
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=['normal', 'attack'], yticklabels=['normal', 'attack'])
        plt.title("Confusion Matrix")
        plt.xlabel("Predicted")
        plt.ylabel("Actual")
        plt.show()

    elif choice == 1:
        print("Analyzing a PCAP file...")
        pcap_file = input("Enter the path to the PCAP file: ")
        model = joblib.load('sip_anomaly_model.pkl')
        print("Model loaded.")

        data = extract_features(pcap_file)
        data.fillna({'sip_status': 0, 'rtp_payload_type': 0, 'sip_method': 'UNKNOWN'}, inplace=True)
        data = pd.get_dummies(data, columns=['protocol', 'sip_method'])

        missing_cols = set(X.columns) - set(data.columns)
        for col in missing_cols:
            data[col] = 0
        data = data[X.columns]

        predictions = model.predict(data)
        print("Analysis complete. Predictions:")
        print(predictions)

    elif choice == 2:
        print("Analyzing live traffic...")
        interface = input("Enter the network interface (e.g., eth0): ")
        duration = int(input("Enter the duration for live capture (in seconds): "))

        model = joblib.load('sip_anomaly_model.pkl')
        print("Model loaded.")

        live_data = extract_live_traffic(interface, duration)
        if live_data.empty:
            print("No traffic captured during the specified duration.")
            return

        live_data.fillna({'sip_status': 0, 'rtp_payload_type': 0, 'sip_method': 'UNKNOWN'}, inplace=True)
        live_data = pd.get_dummies(live_data, columns=['protocol', 'sip_method'])

        missing_cols = set(X.columns) - set(live_data.columns)
        for col in missing_cols:
            live_data[col] = 0
        live_data = live_data[X.columns]

        predictions = model.predict(live_data)
        print("Live Traffic Analysis Predictions:")
        print(predictions)

    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
