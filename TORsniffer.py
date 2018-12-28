from scapy.all import *
import requests
import time, os, stat
import datetime
import optparse


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



parser = optparse.OptionParser()
parser.add_option('-i', '--interface',
    action="store", dest="interface",
    help="query string", default="enp0s3")
parser.add_option('-f', '--file',
    action="store", dest="pcapfile",
    help="query string", default="")
options, args = parser.parse_args()

print("***************************************")
print("* TOR-Sniffer V.1.3 by Reto Schaedler *")
print("***************************************")
checkTorFile('TOR_IP_LIST.txt')
iplist=loadFile('TOR_IP_LIST.txt')
if options.pcapfile=="":
	print("Start sniffer...")
	sniff(filter='tcp and tcp[tcpflags]==tcp-syn',iface=options.interface, store=0, prn=startSniffer)
else:
	print("Read file...")
	sniff(filter='tcp and tcp[tcpflags]==tcp-syn',offline=options.pcapfile, store=0, prn=startSniffer)
