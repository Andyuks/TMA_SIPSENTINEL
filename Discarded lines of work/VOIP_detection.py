from scapy.all import sniff, IP, UDP, TCP

# Common ports used by voip protocols
VOIP_PORTS = {
    'SIP': [5060, 5061],  # SIP ports
    'RTP': list(range(16384, 32767)),  # RTP/RTCP media streams ports
}

def identify_voip_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]

        if UDP in packet:
            udp_layer = packet[UDP]
            src_port, dst_port = udp_layer.sport, udp_layer.dport

            # Check for voip related ports like SIP or RTP (we could detect a specific pattern of sip and rtp)
            if src_port in VOIP_PORTS['SIP'] or dst_port in VOIP_PORTS['SIP']:
                print(f"SIP packet detected: {ip_layer.src} -> {ip_layer.dst} on port {src_port if src_port in VOIP_PORTS['SIP'] else dst_port}")
                return True

            if src_port in VOIP_PORTS['RTP'] or dst_port in VOIP_PORTS['RTP']:
                print(f"RTP/RTCP packet detected: {ip_layer.src} -> {ip_layer.dst} on port {src_port if src_port in VOIP_PORTS['RTP'] else dst_port}")
                return True

    return False

def packet_callback(packet):
    if identify_voip_packet(packet):
        print("VoIP traffic identified.")

def main():
    print("Starting packet sniffing to identify VoIP traffic...")
    try:
        sniff(prn=packet_callback, filter="ip", store=0)
    except KeyboardInterrupt:
        print("Sniffing stopped.")

if __name__ == "__main__":
    main()
