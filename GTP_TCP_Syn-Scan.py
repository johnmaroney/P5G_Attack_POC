import os
import socket
import ipaddress
import subprocess
from scapy.all import *
from scapy.utils import PcapReader

# Variables for GTP tunnel information
gtp_flows = {}
gtp_src_ip = None
gtp_dst_ip = None
capture_duration = 5
sniff_interface = "eth2"  # Specify the interface to sniff on
send_interface = "eth1"  # Specify the interface for sending Nmap traffic

# Modbus variables
modbus_slave_ip = None
modbus_master_ip = None
modbus_slave_mac = "00:50:56:86:23:b8"  # Obtain from SPAN MAC Address going towards Core for ICS Mgt Workstation
modbus_master_mac = "00:e0:4c:68:0a:78"   # Obtain from L2 connection going to RAN or FW port if between

# Function to process GTP packets and extract flow information
def sniff_gtp_info(packet):
    global modbus_master_ip
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
                modbus_master_ip = inner_packet.src
                modbus_slave_ip = inner_packet.dst
                modbus_tcp_payload = bytes(inner_packet[TCP].payload)

                # Check if the flow is not already captured
                if (gtp_src_ip, gtp_dst_ip, gtp_teid) not in gtp_flows:
                    gtp_flows[(gtp_src_ip, gtp_dst_ip, gtp_teid)] = {
                        'modbus_master_ip': modbus_master_ip,
                        'modbus_slave_ip': modbus_slave_ip,
                        'modbus_tcp_payload': modbus_tcp_payload,
                        'gtp_src_ip': gtp_src_ip,  # Add gtp_src_ip and gtp_dst_ip to the flow_info
                        'gtp_dst_ip': gtp_dst_ip,
                        'gtp_teid': gtp_teid
                    }

                    print("Modbus traffic detected!")
                    print("GTP Source IP:", gtp_src_ip)
                    print("GTP Destination IP:", gtp_dst_ip)
                    print("TEID:", gtp_teid)
                    print("Modbus Master IP:", modbus_master_ip)
                    print("Modbus Slave IP:", modbus_slave_ip)
                    print("------------------------")



def send_nmap_packet(target_ip):
    global modbus_master_mac
    global modbus_slave_mac

    if len(gtp_flows) > 0:
        # Get the first flow information
        flow_key, flow_info = next(iter(gtp_flows.items()))
        gtp_src_ip, gtp_dst_ip, gtp_teid = flow_key
        modbus_master_ip = flow_info['modbus_master_ip']
        modbus_slave_ip = flow_info['modbus_slave_ip']

        # Create IP layer for the encapsulated IP packet
        ip_header = IP(src=modbus_slave_ip, dst=modbus_master_ip)  # Swap source and destination IP addresses

        # Create TCP layer for the initial SYN TCP connection
        isn = random.getrandbits(32)
        seq = isn
        tcp_syn = TCP(sport=12345, dport=80, flags="S", seq=seq)  # Set SYN flag

        # Encapsulate TCP SYN packet within GTP payload
        gtp_nmap_syn = ip_header / tcp_syn

        # Calculate the total payload length (GTP header + TCP SYN)
        gtp_header = b'\x30\xff' + (len(gtp_nmap_syn)).to_bytes(2, 'big') + gtp_teid.to_bytes(4, 'big')  # GTP v>

        # Assemble the GTP packet with the TCP SYN packet
        gtp_packet_nmap = Ether(src=modbus_slave_mac, dst=modbus_master_mac) / \
                          IP(src=gtp_dst_ip, dst=gtp_src_ip) / \
                          UDP(sport=2152, dport=2152) / \
                          Raw(load=gtp_header) / IP(dst=str(target_ip), src=modbus_slave_ip) / tcp_syn

        # Send the GTP packet with the TCP SYN packet
        sendp(gtp_packet_nmap, iface=send_interface)
        print(gtp_packet_nmap)


def send_nmap_packet_2(target_ip):
    global modbus_master_mac
    global modbus_slave_mac

    if len(gtp_flows) > 0:
        # Get the first flow information
        flow_key, flow_info = next(iter(gtp_flows.items()))
        gtp_src_ip, gtp_dst_ip, gtp_teid = flow_key
        modbus_master_ip = flow_info['modbus_master_ip']
        modbus_slave_ip = flow_info['modbus_slave_ip']

        # Create IP layer for the encapsulated IP packet
        ip_header = IP(src=modbus_slave_ip, dst=modbus_master_ip)  # Swap source and destination IP addresses

        # Create TCP layer for the initial SYN TCP connection
        isn = random.getrandbits(32)
        seq = isn
        tcp_syn = TCP(sport=12345, dport=80, flags="S", seq=seq)  # Set SYN flag

        # Encapsulate TCP SYN packet within GTP payload
        gtp_nmap_syn = ip_header / tcp_syn

        # Calculate the total payload length (GTP header + TCP SYN)
        gtp_header = b'\x30\xff' + (len(gtp_nmap_syn)).to_bytes(2, 'big') + gtp_teid.to_bytes(4, 'big')  # GTP v>

        # Assemble the GTP packet with the TCP SYN packet
        gtp_packet_nmap = Ether(src=modbus_master_mac, dst=modbus_slave_mac) / \
                          IP(src=gtp_src_ip, dst=gtp_dst_ip) / \
                          UDP(sport=2152, dport=2152) / \
                          Raw(load=gtp_header) / IP(dst=str(target_ip), src=modbus_master_ip) / tcp_syn

        # Send the GTP packet with the TCP SYN packet
        sendp(gtp_packet_nmap, iface=send_interface)
        print(gtp_packet_nmap)


def scan_gtp_flows():
    for flow_info in gtp_flows.values():
        # Perform Nmap scan on both sides of the GTP flow
        subnet_src = ipaddress.IPv4Network(flow_info['modbus_master_ip'] + '/24', strict=False)
        subnet_dst = ipaddress.IPv4Network(flow_info['modbus_slave_ip'] + '/24', strict=False)

        print(f"Scanning subnet {subnet_src} on GTP tunnel {flow_info['gtp_src_ip']} to {flow_info['gtp_dst_ip']}")
        for target_ip in subnet_src.hosts():
            send_nmap_packet(str(target_ip))

        print(f"Scanning subnet {subnet_dst} on GTP tunnel {flow_info['gtp_src_ip']} to {flow_info['gtp_dst_ip']}")
        for target_ip in subnet_dst.hosts():
            send_nmap_packet_2(str(target_ip))


def main():
    try:
        # Sniff GTP tunnel for source and destination IP addresses, TEID, and internal IP addresses
        print("Sniffing GTP tunnels for Nmap traffic to scan subnets...")
        sniff(filter='udp and port 2152', prn=sniff_gtp_info, iface=sniff_interface, timeout=capture_duration)

        # Perform Nmap scans for each GTP flow
        scan_gtp_flows()

    except KeyboardInterrupt:
        # Print captured GTP flows
        print("Captured GTP flows:")
        for flow_key, flow_info in gtp_flows.items():
            gtp_src_ip, gtp_dst_ip, gtp_teid = flow_key
            print("GTP Source IP:", gtp_src_ip)
            print("GTP Destination IP:", gtp_dst_ip)
            print("TEID:", gtp_teid)
            print("Modbus Master IP:", flow_info['modbus_master_ip'])
            print("Modbus Slave IP:", flow_info['modbus_slave_ip'])
            print("------------------------")

if __name__ == "__main__":
    main()
