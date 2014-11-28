#!/usr/bin/env python
"""Wifi Detection Module

Scans the APs at IST-Taguspark via SNMP and retrives the connectd MAC
addreses saving the relevant information.
"""
__author__ = "Artur Balanuta"
__version__ = "1.0.0"
__email__ = "artur.balanuta [at] tecnico.ulisboa.pt"

import netsnmp
import threading
from datetime import datetime
from time import sleep

class SNMPDetector(threading.Thread):

	DEBUG 		= False
	IP_RANGE 	= ('172.20.3.', 1, 70)	# APs ip Range 172.20.3.1-60
	SCAN_DELAY 	= 2						# Time in seconds

	def __init__(self):
		if self.DEBUG:
			print "SNMPDetector.init()"
		threading.Thread.__init__(self)
		self.stopped = True
		self.addreses = dict()

	def stop(self):
		if self.DEBUG:
			print "SNMPDetector.stop()"
		self.stopped = True

	def run(self):
		if self.DEBUG:
			print "SNMPDetector.run()"
		self.stopped = False

		while not self.stopped:
			self.update()
			for x in range(0, self.SCAN_DELAY):
				if not self.stopped:
					sleep(1)

	def update(self):
		if self.DEBUG:
			print "SNMPDetector.update()"

		collection = {
						"2.4Ghz" : dict(),
						"5.0Ghz" : dict()
					}

		for x in range(int(self.IP_RANGE[1]), int(self.IP_RANGE[2])+1):
			ip = self.IP_RANGE[0]+str(x)
			d = self.get_mac_ip(ip)
			for fhz in d:
				if len(d[fhz]) > 0:
					for x in d[fhz]:
						x_mac, x_ip = x.items()[0]
						if not x_ip == "0.0.0.0":
							collection[fhz][x_mac] = [x_ip]

		self.addreses = collection

	def convert_mac(self, var):
		mac = var.split('.')

		if mac[15] == '1':
			ch = '2.4Ghz'
		elif mac[15] == '2':
			ch = '5.0Ghz'

		mac = mac[-6:]
		for x in range(0, len(mac)):
			char = hex(int(mac[x])).split('x')[1].upper()
			if len(char) == 1:
				mac[x] = '0'+char
			else:
				mac[x] = char
		the_mac = mac[0]+':'+mac[1]+':'+mac[2]+':'+mac[3]+':'+mac[4]+':'+mac[5]
		return the_mac, ch


	def get_mac_ip(self, ip):

		oid = '.1.3.6.1.4.1.9.9.273.1.2.1.1.16'
		session = netsnmp.Session( DestHost=ip, Version=2, Community='public',Timeout=10000,\
								   Retries=1, UseNumeric=1)
		session.UseLongNames = 1
		vars = netsnmp.VarList( netsnmp.Varbind(oid) )
		session.walk(vars)

		d = {
			"2.4Ghz" : list(),
			"5.0Ghz" : list()
			}

		for var in vars:
			mac, ch = self.convert_mac(var.tag+"."+var.iid)
			ip = ""
			for c in var.val:
				ip += str(int(c.encode("hex"), 16))+"."
			ip = ip[:-1]
			#print mac, ch, ip
			d[ch].append({mac:ip})

		return d


	def get_adresses(self, frequency):
		if frequency in self.addreses.keys():
			return self.addreses[frequency]
		else:
			return dict()

##Executed if only is the main app
if __name__ == '__main__':

	wd = SNMPDetector()

	try:
		wd.start()
		sleep(3600)
		wd.stop()
	except KeyboardInterrupt:
		wd.stop()
