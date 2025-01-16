import pyshark
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.datasets import load_iris
from sklearn.model_selection import train_test_split
import joblib

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

    return pd.concat(df_list)

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
        'normal'
        ]

dataset = prepare_dataset(pcap_files, labels)
X = dataset.drop(columns='label')
y = dataset['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
model = RandomForestClassifier()
model.fit(X_train, y_train)

joblib.dump(model, 'random_forest_model.pkl')

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print(f'Model accuracy: {accuracy * 100:.2f}%')