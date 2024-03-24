**Packet Sniffer Script**
This Python script is a packet sniffer built using the Scapy library. It captures packets from the network and provides options to filter packets based on IP addresses and ports. The script allows users to specify IP and port filters via command-line arguments, and optionally save the captured packets to an output file. Additionally, it includes a customizable banner that greets users when the script is executed

Features:
Capture packets from the network.
Filter packets based on source or destination IP addresses.
Filter packets based on source or destination ports.
Optionally save captured packets to an output file.
Customizable banner displayed at script execution.

Usage:
python sniffer.py -ip <IP_ADDRESS> -p <PORT> -o <OUTPUT_FILE>
Replace <IP_ADDRESS> with the desired IP address, <PORT> with the desired port, and <OUTPUT_FILE> with the name of the output file to save captured packets. Use -h or --help for detailed usage instructions.
