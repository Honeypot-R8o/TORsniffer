# TORsniffer
# Installation on Ubuntu 18.04:
sudo apt-get update
sudo apt-get install python3
sudo apt install python3-pip
sudo pip3 install scapy
sudo pip3 install requests
sudo pip3 install time
sudo pip3 install datetime

#set interface on line 6
#change line 71/73 to use PCAP-File instead of sniffer-mode
#run the TOR-Sniffer
sudo python3 TORsniffer.py

# example:

sudo python3 TORsniffer.py 
***************************************
* TOR-Sniffer V.1.2 by Reto Schaedler *
***************************************
TOR-IP-File age in seconds: 1222
TOR-IP-File is up to date.
Read TOR-IP-File
Start sniffer...
***************************************
TOR-Session-Detected:
192.168.200.209 -> 199.249.223.66
Time: 28-12-2018 02:55:27

***************************************
TOR-Session-Detected:
192.168.200.209 -> 138.201.3.75
Time: 28-12-2018 02:55:35
