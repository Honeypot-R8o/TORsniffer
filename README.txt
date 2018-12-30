# TORsniffer
# Installation on Ubuntu 18.04:
sudo apt-get update
sudo apt-get install python3
sudo apt install python3-pip
sudo pip3 install scapy
sudo pip3 install requests
sudo pip3 install time
sudo pip3 install datetime

#run the TOR-Sniffer with interface -i:
sudo python3 TORsniffer.py -i enp0s3
#run the TOR-Sniffer with PCAP-File:
sudo python3 TORsniffer.py -f sniffFile.pcap

# use a managed switch with port-mirroring to sniff the internet traffic
# example:

sudo python3 TORsniffer.py -i enp0s3
***************************************
* TOR-Sniffer V.1.3 by Reto Schaedler *
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
