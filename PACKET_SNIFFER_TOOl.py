import argparse
from scapy.all import *

print("*************************************************")
print("*                                               *")
print("*               WELCOME TO SALMAN               *")
print("*              PACKET SNIFFER TOOl              *")
print("*                                               *")
print("*************************************************")
print()

parser = argparse.ArgumentParser(description="Packet sniffer with optional IP and port filters")
parser.add_argument("-ip", metavar="IP", type=str, help="Filter packets for a specific IP address")
parser.add_argument("-p", metavar="port", type=int, help="Filter packets for a specific port")
parser.add_argument("-o", metavar="output_file", type=str, help="Output file name")
args = parser.parse_args()

def packet_callback(packet):
    if IP in packet:
        if args.ip and packet[IP].src != args.ip and packet[IP].dst != args.ip:
            return
        if args.p and (TCP not in packet or packet[TCP].sport != args.p and packet[TCP].dport != args.p):
            return

        output = f"Source IP: {packet[IP].src}, Source Port: {packet.sport} --> Destination IP: {packet[IP].dst}, Destination Port: {packet.dport}"
        print(output)
        if args.o:
            with open(args.o, "a") as f:
                f.write(output + "\n")

sniff(prn=packet_callback, store=0)
