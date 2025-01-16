import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import ipaddress
import scapy.all as scapy
from scapy.layers.inet import IP, UDP
from collections import defaultdict
import threading
import time
from datetime import datetime, timedelta
import logging
import pickle
import re
import geoip2.database
import csv
import os

class SIPPacketAnalyzer:
    def __init__(self):
        self.packet_buffer = defaultdict(list)
        self.analysis_window = 60
        self.spanish_ranges = [
            '80.0.0.0/8',    # Telefonica
            '85.0.0.0/8',    # Orange Espnha
            '213.0.0.0/8',   # Vodafone Espanha
            '217.0.0.0/8'    # Various Spanish ISPs
        ]
        self.setup_geoip()
        
    def setup_geoip(self):
        try:
            self.geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        except:
            print("Warning: GeoIP database not found. Location features will be disabled.")
            self.geo_reader = None

    def get_location_data(self, ip):
        if not self.geo_reader:
            return None
        try:
            response = self.geo_reader.city(ip)
            return {
                'country': response.country.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'time_zone': response.location.time_zone
            }
        except:
            return None

    def analyze_sip_packet(self, packet):
        if not (IP in packet and UDP in packet):
            return None
            
        features = {
            'timestamp': datetime.now(),
            'source_ip': packet[IP].src,
            'destination_ip': packet[IP].dst,
            'packet_size': len(packet),
            'ttl': packet[IP].ttl,
            'protocol': 'SIP'
        }
        
        # Location features
        source_location = self.get_location_data(features['source_ip'])
        if source_location:
            features.update({
                'source_country': source_location['country'],
                'source_timezone': source_location['time_zone'],
                'source_latitude': source_location['latitude'],
                'source_longitude': source_location['longitude']
            })
        else:
            features.update({
                'source_country': 'Unknown',
                'source_timezone': 'Unknown',
                'source_latitude': 0,
                'source_longitude': 0
            })
            
        # Pre-call analysis
        current_hour = datetime.now().hour
        features.update({
            'is_spanish_ip': self.is_spanish_ip(features['source_ip']),
            'time_of_day': current_hour,
            'is_working_hours': 9 <= current_hour <= 18,
            'is_spanish_hours': 8 <= current_hour <= 22,
            'day_of_week': datetime.now().weekday(),
        })
        
        return features



class VoIPSpamDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = RandomForestClassifier(
            n_estimators=300,
            max_depth=20,
            class_weight='balanced',
            random_state=42
        )
        self.sip_analyzer = SIPPacketAnalyzer()
        self.feature_history = defaultdict(list)
        self.spam_threshold = 0.75
        self.detected_threats = []
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            filename='voip_spam_detector.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def extract_features(self, packet_data):
        if isinstance(packet_data, dict):
            packet_data = pd.DataFrame([packet_data])
            
        features = pd.DataFrame()
        
        # Basic network features
        features['ip_version'] = packet_data['source_ip'].apply(
            lambda x: ipaddress.ip_address(x).version)
        features['packet_size'] = packet_data['packet_size']
        features['ttl'] = packet_data['ttl']
        
        # Location-based features
        if 'source_country' in packet_data.columns:
            features = pd.concat([
                features,
                pd.get_dummies(packet_data['source_country'], prefix='country')
            ], axis=1)
            
        # Temporal features
        features['is_working_hours'] = packet_data['is_working_hours'].astype(int)
        features['day_of_week'] = packet_data['day_of_week']
        features['time_of_day'] = packet_data['time_of_day']
        
        # Behavioral features
        features['payload_length'] = packet_data['payload_length']
        
        return features

    def train(self, training_data):
        logging.info("Starting model training...")
        X = self.extract_features(training_data)
        y = training_data['is_spam']
        
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        
        self.model.fit(X_train_scaled, y_train)
        
        y_pred = self.model.predict(X_val_scaled)
        report = classification_report(y_val, y_pred)
        logging.info(f"Training complete. Performance metrics:\n{report}")
        print(f"Training Performance:\n{report}")
        
        self.save_model()
        return self

    def predict_packet(self, packet_features):
        features = self.extract_features(packet_features)
        scaled_features = self.scaler.transform(features)
        probability = self.model.predict_proba(scaled_features)[0][1]
        is_spam = probability > self.spam_threshold
        
        if is_spam:
            threat_info = {
                'timestamp': datetime.now(),
                'source_ip': packet_features['source_ip'],
                'probability': probability,
                'features': packet_features
            }
            self.detected_threats.append(threat_info)
            logging.warning(f"Potential VoIP spam detected from {packet_features['source_ip']} (probability: {probability:.2f})")
            
        return is_spam, probability

    def save_model(self, filename='voip_spam_model.pkl'):
        with open(filename, 'wb') as f:
            pickle.dump((self.model, self.scaler), f)
        logging.info(f"Model saved to {filename}")
            
    def load_model(self, filename='voip_spam_model.pkl'):
        with open(filename, 'rb') as f:
            self.model, self.scaler = pickle.load(f)
        logging.info(f"Model loaded from {filename}")

    def start_real_time_detection(self, interface="eth0"):
        print(f"Starting real-time detection on interface {interface}")
        logging.info(f"Starting real-time detection on interface {interface}")
        self.running = True
        self.capture_thread = threading.Thread(target=self._packet_capture_loop, args=(interface,))
        self.analysis_thread = threading.Thread(target=self._analysis_loop)
        
        self.capture_thread.start()
        self.analysis_thread.start()
        
    def stop_real_time_detection(self):
        self.running = False
        self.capture_thread.join()
        self.analysis_thread.join()
        logging.info("Real-time detection stopped")

    def _packet_capture_loop(self, interface):
        def packet_callback(packet):
            if not self.running:
                return
                
            if IP in packet and UDP in packet:
                features = self.sip_analyzer.analyze_sip_packet(packet)
                if features:
                    is_spam, probability = self.predict_packet(features)
                    if is_spam:
                        print(f"Potential spam call detected from {features['source_ip']} (probability: {probability:.2f})")
                    
        try:
            scapy.sniff(iface=interface, prn=packet_callback, store=False)
        except Exception as e:
            logging.error(f"Packet capture error: {str(e)}")

    def _analysis_loop(self):
        while self.running:
            time.sleep(self.sip_analyzer.analysis_window)
            if self.detected_threats:
                self._generate_threat_report()

    def _generate_threat_report(self):
        report_file = f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(report_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Source IP', 'Probability', 'Country', 'Spam Words Detected'])
            for threat in self.detected_threats:
                writer.writerow([
                    threat['timestamp'],
                    threat['source_ip'],
                    threat['probability'],
                    threat['features'].get('source_country', 'Unknown')
                ])
        self.detected_threats = []
        logging.info(f"Threat report generated: {report_file}")

def generate_training_data(num_samples=1000):
    eu_countries = ['Spain', 'France', 'Portugal', 'Germany', 'Italy']
    high_risk_countries = ['Russia', 'China', 'Nigeria', 'India', 'Brazil']
    spain_tz = 'Europe/Madrid'
    
    data = []
    
    # Legitimate calls (60%)
    for _ in range(int(num_samples * 0.6)):
        timestamp = datetime.now() - timedelta(hours=np.random.randint(0, 168))
        is_spanish = np.random.choice([True, False], p=[0.7, 0.3])
        
        if is_spanish:
            source_ip = f"80.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
            source_country = 'Spain'
        else:
            source_ip = f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}"
            source_country = np.random.choice(eu_countries, p=[0.1, 0.3, 0.2, 0.2, 0.2])

        sample = {
            'timestamp': timestamp,
            'source_ip': source_ip,
            'destination_ip': f"85.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
            'packet_size': np.random.normal(500, 100),
            'payload_length': np.random.normal(400, 80),
            'ttl': np.random.randint(50, 64),
            'source_country': source_country,
            'source_timezone': spain_tz if is_spanish else 'UTC',
            'time_of_day': timestamp.hour,
            'is_working_hours': 9 <= timestamp.hour <= 18,
            'day_of_week': timestamp.weekday(),
            'is_spanish_hours': 8 <= timestamp.hour <= 22,
            'is_spanish_ip': is_spanish,
            'is_spam': 0
        }
        data.append(sample)
    
    # Spam calls (40%)
    for _ in range(int(num_samples * 0.4)):
        timestamp = datetime.now() - timedelta(hours=np.random.randint(0, 168))
        source_country = np.random.choice(high_risk_countries, p=[0.3, 0.3, 0.2, 0.1, 0.1])
        
        sample = {
            'timestamp': timestamp,
            'source_ip': f"{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
            'destination_ip': f"85.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
            'packet_size': np.random.normal(300, 150),
            'payload_length': np.random.normal(200, 100),
            'ttl': np.random.randint(30, 50),
            'source_country': source_country,
            'source_timezone': 'UTC',
            'time_of_day': timestamp.hour,
            'is_working_hours': 9 <= timestamp.hour <= 18,
            'day_of_week': timestamp.weekday(),
            'is_spanish_hours': 8 <= timestamp.hour <= 22,
            'is_spanish_ip': False,
            'is_spam': 1
        }
        data.append(sample)
    
    return pd.DataFrame(data)


def main():
    print("VoIP Spam Detector")
    print("1. Train new model with synthetic data")
    print("2. Start real-time detection")
    choice = input("Enter your choice (1/2): ")
    
    detector = VoIPSpamDetector()
    
    if choice == '1':
        print("Generating synthetic training data...")
        training_data = generate_training_data(num_samples=5000)
        print("Training new model...")
        detector.train(training_data)
        print("Model trained and saved successfully!")
            
    elif choice == '2':
        try:
            detector.load_model()
            print("Model loaded successfully!")
            interface = input("Enter network interface to monitor (e.g., eth0): ")
            detector.start_real_time_detection

            
            print("Press Ctrl+C to stop...")
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\nStopping detection...")
            detector.stop_real_time_detection()
        except FileNotFoundError:
            print("Error: No trained model found. Please train the model first (option 1).")
        except Exception as e:
            print(f"Error: {str(e)}")
    else:
        print("Select valid option (1 or 2)!")
            
if __name__ == "__main__":
    main()
