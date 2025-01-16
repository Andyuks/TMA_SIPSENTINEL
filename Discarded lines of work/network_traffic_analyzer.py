# Script for network traffic analysis
from scapy.all import *
from datetime import datetime
import json
import logging

# SIP Traffic Analyzer class
class SIPTrafficAnalyzer:
    # Initialize SIP Traffic Analyzer
    def __init__(self, interface='eth0', output_file='sip_traffic.json'):
        self.interface = interface
        self.output_file = output_file
        self.captured_traffic = []
        self.processed_packets = set() # Track processed packets
        
        # Configure logging
        logging.basicConfig(level=logging.INFO, 
                            format='%(asctime)s - %(levelname)s: %(message)s')

    # Check if packet is a SIP packet
    def is_sip_packet(self, packet):
        return (UDP in packet and 
                (packet[UDP].dport == 5060 or packet[UDP].sport == 5060))
    

    # Analyze SIP packet
    def analyze_sip_packet(self, packet):
        try:
            sip_info = {
                'timestamp': str(datetime.now()),
                'source_ip': packet[IP].src,
                'dest_ip': packet[IP].dst,
                'source_port': packet[UDP].sport,
                'dest_port': packet[UDP].dport,
                'length': len(packet),
                'sip_method': None
            }

            # Extract payload and detect SIP method
            if Raw in packet:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                sip_info['payload'] = payload
                
                # Generate a unique identifier for duplication
                packet_id = hash((packet[IP].src, packet[IP].dst, packet[UDP].sport, packet[UDP].dport, payload))
                
                if packet_id in self.processed_packets:
                    return  # Skip duplicate packets
                
                self.processed_packets.add(packet_id)
                
                # Detect SIP method
                sip_methods = ['INVITE', 'REGISTER', 'OPTIONS', 'BYE', 'NOTIFY', 'SUBSCRIBE']
                for method in sip_methods:
                    if method in payload:
                        sip_info['sip_method'] = method
                        break

            self.captured_traffic.append(sip_info)
            logging.info(
                f"Captured SIP Packet: {sip_info['source_ip']} -> {sip_info['dest_ip']}, "
                f"Method: {sip_info['sip_method'] or 'Unknown'}"
            )
        
        except Exception as e:
            logging.error(f"Error processing packet: {e}")

    # Capture network traffic for specified duration
    def capture_traffic(self, duration=60):
        logging.info(f"Starting SIP traffic capture on {self.interface} for {duration} seconds")
        
        # Capture packets
        packets = sniff(iface=self.interface, 
                        lfilter=self.is_sip_packet, 
                        prn=self.analyze_sip_packet, 
                        timeout=duration)
                        
    # Save captured traffic to JSON file
    def save_traffic_log(self):
        with open(self.output_file, 'w') as f:
            json.dump(self.captured_traffic, f, indent=2)
        
        logging.info(f"Saved {len(self.captured_traffic)} packets to {self.output_file}")

# Main function
if __name__ == '__main__':
    analyzer = SIPTrafficAnalyzer()
    analyzer.capture_traffic(duration=120)  # Capture for 2 minutes
    analyzer.save_traffic_log()