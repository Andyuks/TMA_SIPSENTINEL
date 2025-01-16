import pyshark
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import time
from collections import defaultdict

class VoIPAnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.feature_columns = None
        
    def extract_features(self, pcap_file):
        cap = pyshark.FileCapture(pcap_file)
        features = []
        flow_stats = defaultdict(lambda: {'packet_counts': 0, 'byte_counts': 0, 'timestamps': []})
        
        for pkt in cap:
            try:
                # Basic packet features
                packet_size = int(pkt.length)
                protocol = pkt.highest_layer
                time_stamp = float(pkt.sniff_timestamp)
                
                # Transport layer features
                if hasattr(pkt, 'transport_layer'):
                    src_port = int(pkt[pkt.transport_layer].srcport)
                    dst_port = int(pkt[pkt.transport_layer].dstport)
                    
                    # Create flow key (bidirectional)
                    flow_key = tuple(sorted([f"{pkt.ip.src}:{src_port}", 
                                          f"{pkt.ip.dst}:{dst_port}"]))
                else:
                    continue
                
                # Update flow statistics
                flow_stats[flow_key]['packet_counts'] += 1
                flow_stats[flow_key]['byte_counts'] += packet_size
                flow_stats[flow_key]['timestamps'].append(time_stamp)
                
                # SIP-specific features
                sip_features = {
                    'sip_status': None,
                    'sip_method': None,
                    'sip_user_agent': None,
                    'sip_call_id': None,
                    'has_sdp': False,
                    'auth_present': False
                }
                
                if 'SIP' in pkt:
                    sip_features.update({
                        'sip_status': pkt.sip.Status_Code if hasattr(pkt.sip, 'Status_Code') else None,
                        'sip_method': pkt.sip.Method if hasattr(pkt.sip, 'Method') else None,
                        'sip_user_agent': pkt.sip.User_Agent if hasattr(pkt.sip, 'User_Agent') else None,
                        'sip_call_id': pkt.sip.Call_ID if hasattr(pkt.sip, 'Call_ID') else None,
                        'has_sdp': hasattr(pkt, 'sdp'),
                        'auth_present': hasattr(pkt.sip, 'auth') or hasattr(pkt.sip, 'proxy_authenticate')
                    })
                
                # RTP-specific features
                rtp_features = {
                    'rtp_payload_type': None,
                    'rtp_sequence_number': None,
                    'rtp_timestamp': None,
                    'rtp_ssrc': None
                }
                
                if 'RTP' in pkt:
                    rtp_features.update({
                        'rtp_payload_type': int(pkt.rtp.payload_type),
                        'rtp_sequence_number': int(pkt.rtp.sequence_number),
                        'rtp_timestamp': int(pkt.rtp.timestamp),
                        'rtp_ssrc': int(pkt.rtp.ssrc, 16)
                    })
                
                # Combine all features
                packet_features = {
                    'packet_size': packet_size,
                    'protocol': protocol,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'time': time_stamp,
                    'flow_key': str(flow_key),
                    **sip_features,
                    **rtp_features
                }
                
                features.append(packet_features)
                
            except AttributeError:
                continue
        
        cap.close()
        df = pd.DataFrame(features)
        
        # Add flow-based features
        df['packets_in_flow'] = df['flow_key'].map({k: v['packet_counts'] for k, v in flow_stats.items()})
        df['bytes_in_flow'] = df['flow_key'].map({k: v['byte_counts'] for k, v in flow_stats.items()})
        
        # Calculate flow duration and packet rate
        for flow_key, stats in flow_stats.items():
            if len(stats['timestamps']) > 1:
                duration = max(stats['timestamps']) - min(stats['timestamps'])
                packet_rate = stats['packet_counts'] / duration if duration > 0 else 0
                byte_rate = stats['byte_counts'] / duration if duration > 0 else 0
            else:
                duration = 0
                packet_rate = 0
                byte_rate = 0
                
            mask = df['flow_key'] == str(flow_key)
            df.loc[mask, 'flow_duration'] = duration
            df.loc[mask, 'packet_rate'] = packet_rate
            df.loc[mask, 'byte_rate'] = byte_rate
        
        return df

    def prepare_dataset(self, pcap_files, labels):
        df_list = []
        for pcap_file, label in zip(pcap_files, labels):
            df = self.extract_features(pcap_file)
            df['label'] = label
            df_list.append(df)
        
        dataset = pd.concat(df_list, ignore_index=True)
        
        # Add advanced features
        self._add_advanced_features(dataset)
        
        return dataset
    
    def _add_advanced_features(self, df):
        # Time-based features
        df['inter_packet_time'] = df.groupby('flow_key')['time'].diff().fillna(0)
        df['time_since_flow_start'] = df.groupby('flow_key')['time'].transform(
            lambda x: x - x.iloc[0])
        
        # Statistical features per flow
        flow_stats = df.groupby('flow_key').agg({
            'packet_size': ['mean', 'std', 'max', 'min'],
            'inter_packet_time': ['mean', 'std'],
            'packets_in_flow': 'first',
            'bytes_in_flow': 'first'
        }).reset_index()
        
        # Flatten column names
        flow_stats.columns = ['flow_key'] + [
            f'{col[0]}_{col[1]}' for col in flow_stats.columns[1:]]
        
        # Merge back to original dataframe
        df = df.merge(flow_stats, on='flow_key', how='left')
        
        # SIP-specific features
        df['sip_auth_ratio'] = df.groupby('flow_key')['auth_present'].transform('mean')
        df['unique_sip_methods'] = df.groupby('flow_key')['sip_method'].transform('nunique')
        
        # RTP-specific features
        df['rtp_sequence_gaps'] = df.groupby(['flow_key', 'rtp_ssrc'])['rtp_sequence_number'].transform(
            lambda x: x.diff().fillna(1) - 1)
        
        return df
    
    def train(self, X, y):
        # Define parameter grid for GridSearchCV
        param_grid = {
            'n_estimators': [100, 200, 300],
            'max_depth': [10, 20, 30, None],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4]
        }
        
        # Initialize and train model with GridSearchCV
        base_model = RandomForestClassifier(random_state=42, class_weight='balanced')
        self.model = GridSearchCV(base_model, param_grid, cv=5, n_jobs=-1, scoring='f1_weighted')
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled, y)
        
        # Store feature columns
        self.feature_columns = X.columns
        
        return self.model.best_params_
    
    def predict(self, X):
        if self.model is None:
            raise ValueError("Model not trained yet!")
            
        # Ensure all feature columns exist
        for col in self.feature_columns:
            if col not in X.columns:
                X[col] = 0
                
        X = X[self.feature_columns]
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)
    
    def evaluate(self, X_test, y_test):
        y_pred = self.predict(X_test)
        
        # Calculate and plot metrics
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        cm = confusion_matrix(y_test, y_pred)
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues")
        plt.title("Confusion Matrix")
        plt.xlabel("Predicted")
        plt.ylabel("Actual")
        plt.show()
        
        # Feature importance analysis
        feature_importance = pd.DataFrame({
            'feature': self.feature_columns,
            'importance': self.model.best_estimator_.feature_importances_
        }).sort_values('importance', ascending=False)
        
        plt.figure(figsize=(12, 6))
        sns.barplot(data=feature_importance.head(15), x='importance', y='feature')
        plt.title("Top 15 Most Important Features")
        plt.show()
        
        return feature_importance

def main():
    detector = VoIPAnomalyDetector()
    
    print("Select an option:")
    print("0 - Train and save model")
    print("1 - Analyze a PCAP file using the saved model")
    print("2 - Analyze live traffic using the saved model")
    
    choice = int(input("Enter your choice: "))
    
    if choice == 0:
        print("Training and saving the model...")
        dataset = detector.prepare_dataset(pcap_files, labels)
        
        # Prepare features for training
        X = dataset.select_dtypes(include=['float64', 'int64'])
        y = dataset['label']
        
        # Split dataset
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y)
        
        # Train model
        best_params = detector.train(X_train, y_train)
        print("\nBest parameters:", best_params)
        
        # Evaluate model
        feature_importance = detector.evaluate(X_test, y_test)
        
        # Save model
        joblib.dump((detector.model, detector.scaler, detector.feature_columns), 
                   'voip_anomaly_detector.pkl')
        print("\nModel saved as 'voip_anomaly_detector.pkl'")
        
    elif choice in [1, 2]:
        # Load model
        model, scaler, feature_columns = joblib.load('voip_anomaly_detector.pkl')
        detector.model = model
        detector.scaler = scaler
        detector.feature_columns = feature_columns
        
        if choice == 1:
            pcap_file = input("Enter the path to the PCAP file: ")
            data = detector.extract_features(pcap_file)
        else:
            interface = input("Enter the network interface (e.g., eth0): ")
            duration = int(input("Enter the duration for live capture (in seconds): "))
            # Implementation for live capture...
            
        predictions = detector.predict(data)
        print("\nAnalysis complete. Predictions:", predictions)
        print("\nDetected anomalies:", sum(predictions == 'attack'))
        
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
