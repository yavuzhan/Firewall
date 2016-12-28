import os
from scapy.all import *
from termcolor import colored
conf.verb = 0

toplam, beacon, probereq, proberes = 0, 0, 0, 0
ssidlist   = []
bssidlist  = []

def Parser(pkt):
	global beacon, probereq, proberes, hidden, toplam
	toplam += 1
	if pkt.haslayer(Dot11Beacon):
		ssid = pkt.info
		mac  = pkt.addr2
		beacon += 1
		if mac not in bssidlist:
			bssidlist.append(mac)
			ssidlist.append(ssid)

	elif pkt.haslayer(Dot11ProbeReq):
		ssid = pkt.info
		mac  = pkt.addr2
		probereq += 1
		if mac not in bssidlist:
			bssidlist.append(mac)
			ssidlist.append(ssid)

	elif pkt.haslayer(Dot11ProbeResp):
		ssid = pkt.info
		mac  = pkt.addr2
		proberes += 1
		if mac not in bssidlist:
			bssidlist.append(mac)
			ssidlist.append(ssid)


if __name__ == "__main__":
	os.system("reset")
	sniff(offline="/home/Desktop/network/scapy_e.pcap", prn=Parser)
	print("Toplam paket sayisi : " "green" ,toplam)
	print("Beacon      : ", "green"), beacon
	print("ProbeR      : ", "green"), probereq
	print("ProbeResp   : ", "green"), proberes
	print("\nSSIDList    : ", "green"), ssidlist
	print("\nBSSIDList   : ", "green"), bssidlist
