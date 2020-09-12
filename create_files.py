import os
import sys

# set the wireless interface
line1="interface="+ sys.argv[1] + "\n"
# set the network name
line2="ssid=" + sys.argv[2] + "\n"
# set the channel
line3="channel=1\n"
# set the driver
line4="driver=nl80211\n" # the router driver


try:
    os.remove("hostapd.conf")
except OSError:
    pass
hostapd_file=open("hostapd.conf", "a+")
hostapd_file.write(line1)
hostapd_file.write(line2)
hostapd_file.write(line3)
hostapd_file.write(line4)

# set the wireless interface
line1="interface="+sys.argv[1]+"\n"
# set the IP range for the clients
line2="dhcp-range=10.0.0.10,10.0.0.100,8h\n"

# set the gateway IP adress
line3="dhcp-option=3,10.0.0.1\n" # dhcp address

# set DNS server address
line4="dhcp-option=6,10.0.0.1\n" # dns address

# set routing for any request
line5="address=/#/10.0.0.1\n"
# routing by different os request
line6="address=/clients3.google.com/10.0.0.1\naddress=/ipv6.msftncsi.com/10.0.0.1\naddress=/www.msftncsi.com/10.0.0.1\n"

try:
    os.remove("dnsmasq.conf")
except OSError:
    pass
dnsmasq_file=open("dnsmasq.conf", "a+")
dnsmasq_file.write(line1)
dnsmasq_file.write(line2)
dnsmasq_file.write(line3)
dnsmasq_file.write(line4)
dnsmasq_file.write(line5)
dnsmasq_file.write(line6)


