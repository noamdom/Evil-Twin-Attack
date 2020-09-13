# Evil Twin Attack Tool

## Background
* This project is an exercise in a cyber course, and has only education
goals.
* This tool use some theoretical concepts which will be explained [below](#theoretical-concepts).


### Requirements 
* scapy 
* gnome-terminal
* dnsmasq
* hostapd
* locate the 'html' directory in '/var/www/html'


### Tips
* if you have problem like none avilable network/SIOCADDRT try to 
reconnect the adapters and restart the process


## Theoretical Concepts

### Libraries and used services
* sccapy -  a python library to manipulate packtes
* hostapd and dnsmasq - services for creating AP

### Sniff function (from scapy doc)
sniff has an argument prn that allows you to pass a function that executes
 with each packet sniffed. The intended purpose of this function is to control 
 how the packet prints out in the console allowing you to replace the default 
 packet printing display with a format of your choice.
 
The prn argument is defined as: function to apply to each packet.


### Beacon frame - in sniff (a scapy function)
* Becoan frame is one of the management frames in IEEE802.11 based WLAN
* its contain all the information about the network
* Becoan frame are transmitted periodically to announce the presence
 of a wirless LAN
* Components:
    * Timestamp -  This helps with synchronization
    * Interval (TU) - This is the time interval between beacon transmission
    * SSID - service set ID -  the network name

### Iptables - while playing with the firewall
* Tables
    * Filter - default to go with this rules
    * NAT -  Network address translation
    * Mangle - modify IP headers
    * Raw - for connection tracking
    * Security - set SELinux taging to package
* Chains
    * Pre-Routing - apply to incoming packet , run before any routing decision. 
    * Input - post pre-routing , when packet enters to network stack.
    * Forward -  packet routed  through the system.
    * output - packet originated & going out.
    * post routing - after routing decision & packet going on wire.
    
        Traversal order : -> pre -> input -> forward -> output ->
* Rules
    * User define command ,to manipulate the network traffic
    * As each chain is called the packet will check against the rule - in order


## References
* https://www.thepythoncode.com/search?q=scapy
* https://www.pentesteracademy.com/course?id=14
* https://www.thepythoncode.com/article/create-fake-access-points-scapy
* https://www.youtube.com/watch?v=vbhr4csDeI4&ab_channel=XPSTECH
* https://en.wikipedia.org/wiki/Beacon_frame#:~:text=Beacon%20frame%20is%20one%20of,members%20of%20the%20service%20set.