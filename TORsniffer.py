from scapy.all import *
import requests
import time, os, stat
import datetime

interface='enp0s3'

def file_age_in_seconds(filename):
	return time.time() - os.stat(filename)[stat.ST_MTIME]

def downloadTorIPlist(filenameTOR):
	print("Download TOR IP List...")
	print(filenameTOR)
	url='https://www.dan.me.uk/torlist/'
	r = requests.get(url, allow_redirects=True)
	#print(r.content)
	f=open(filenameTOR, 'wb').write(r.content)
	#f.close()	


def checkTorFile(filenameTOR):
	if os.path.isfile(filenameTOR):
		print("TOR-IP-File age in seconds: " + str(int(file_age_in_seconds(filenameTOR))))
		if file_age_in_seconds(filenameTOR) > 3600:
			# Webserver has a download limit...
			print("TOR-IP-File is older than 1h.")
			downloadTorIPlist(filenameTOR)
		else:
			print("TOR-IP-File is up to date.")
	else:
		print("TOR-IP-File doesn't exist.")
		downloadTorIPlist(filenameTOR)

def loadFile(filenameTOR):
	print("Read TOR-IP-File")
	f=open(filenameTOR, 'r')
	iplist=[]
	x=0
	for line in f:
		iplist.append(line)
		x=x+1
	f.close()
	if (x<1000):
		sys.exit("TOR-IP-File not OK")
	return(iplist)

def startSniffer(pkt):
	global iplist
	sys.stdout.flush()
	if IP in pkt:
		ip_src=pkt[IP].src
		ip_dst=pkt[IP].dst

		for line in iplist:
			if  str(pkt[IP].dst) in str(line):
				print("***************************************")
				print('TOR-Session-Detected:')
				print(str(ip_src) + " -> " + str(ip_dst))
				print ("Time:",datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S'))
				print()
				sys.stdout.flush()



print("***************************************")
print("* TOR-Sniffer V.1.2 by Reto Schaedler *")
print("***************************************")
checkTorFile('TOR_IP_LIST.txt')
iplist=loadFile('TOR_IP_LIST.txt')
print("Start sniffer...")
startSniffer(iplist)
sniff(filter='tcp and tcp[tcpflags]==tcp-syn',iface=interface, store=0, prn=startSniffer)
# Read pcap-file instead of sniff:
#sniff(filter='tcp and tcp[tcpflags]==tcp-syn',offline='file.pcap', store=0, prn=startSniffer)
