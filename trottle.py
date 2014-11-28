#!/usr/bin/python

import sys
import signal
import subprocess
import logging
from time import sleep
from threading import Thread
from datetime import datetime
from termcolor import colored, cprint
from filter import Filter
from errors import DeviceError, KernelError
from snmp_macs import SNMPDetector

class TShapper(Thread):

	N_TOKENS        		= 8000
	SLEEP_INTERVAL  		= 2		#Seconds
	FILTER_DELETE_INTERVAL	= 30 		#Seconds
	OLD_DEVICES_TIMEOUT 	= 300 		#Seconds
	USE_SNMP				= True

	def __init__(self):
		Thread.__init__(self)
		logging.basicConfig(filename='trottle.log',level=logging.DEBUG)
		logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s',\
						 	datefmt='%m/%d/%Y %I:%M:%S %p')

		self.stopped = False
		self.active_filters = 0
		self.filter_delete_counter = 0
		self.tokens			= list()
		self.devices 		= dict()
		self.max_devices 	= {
								'Number': 0,
								'Time'  : datetime.now()
								}
		self.speed 			= {
								'Down'			: 0,
								'Up'			: 0,
								'Last_Update'	: datetime.now()
								}

		self.filter = Filter()
		self.generate_tokens()
		if self.USE_SNMP:
			self.SNMPDetector = SNMPDetector()
			self.SNMPDetector.start()

	def generate_tokens(self):
		for i in range(1, self.N_TOKENS+1):
			self.tokens.append(i)

	def get_token(self):
		return self.tokens.pop(0)

	def release_token(self, token):
		self.tokens.append(token)

	def stop(self):
		self.stopped = True

		#Deletes the TC Rules
		self.filter.destroy_tc_rules()

		if self.USE_SNMP:
			self.SNMPDetector.stop()

	def restart(self):
		#Deletes the TC Rules
		self.filter.destroy_tc_rules()

		#Restarts Objects
		self.__init__()

		#Starts the new TC Rules
		self.filter.init_tc_rules()

	def run(self):

		#Starts the new TC Rules
		self.filter.init_tc_rules()

		#Updates the TC Rules
		while not self.stopped:

			try:
				self.update()
			except KernelError as e:
				cprint("KERNEL ERROR: Restarting ", 'red')
				logging.warning("KernelError:"+str(e))
				sleep(2)
				self.restart()

			sleep(self.SLEEP_INTERVAL)

	def update(self):
		#cprint("Update", 'white')

		if self.USE_SNMP:
			updated_devices = self.get_devices_adresses_from_snmp()
		else:
			updated_devices = self.get_devices_adresses()
		
		for device_mac, ips in updated_devices.items():
			self.update_device(device_mac, ips)

		self.clean_old_devices()

		if len(self.devices) > self.max_devices['Number']:
			self.max_devices['Number'] = len(self.devices)
			self.max_devices['Time'] = datetime.now()

		cprint("Current Clients/Max:"+str(len(self.devices))+"/"+\
				str(self.max_devices['Number'])+" at "+\
				str(self.max_devices['Time'])+" TokensUsed:"+\
				str(self.N_TOKENS - len(self.tokens))+" ActiveFilters:"+\
				str(self.active_filters)+self.get_speed(), 'green')


	def clean_old_devices(self):
		for device_mac, obj in self.devices.items():
			if (datetime.now() - obj["last_seen"]).total_seconds() > self.OLD_DEVICES_TIMEOUT:
				#obj = self.devices[device_mac]
				token = obj["token"]

				#Delete Filters
				for ip in obj["ips"]:
					self.filter.tc_del_filter(token, ip, obj)
					self.active_filters -= 2

				#Delete Class
				self.filter.tc_del_class(token, obj)
				del self.devices[device_mac]
				self.release_token(token)

	def update_device(self, device_mac, ips):

		#Add new Device
		if device_mac not in self.devices.keys():
			obj	  = { 	"mac":device_mac,
					"token":self.get_token(),
					"ips":ips,
					"last_seen":datetime.now(),
					"prefs": { "lan": dict(), "wan": dict() }
					}

			self.devices[device_mac] = obj
			self.filter.tc_add_device(obj)

			for ip in ips:
				self.filter.tc_add_filter(obj['token'], ip, obj)
				self.active_filters += 2

		#Modify Existing Device Rules
		else:
			old_ips = set(self.devices[device_mac]["ips"])
			discovered_ips = set(ips)
			ips_to_delete = old_ips - discovered_ips
			ips_to_add = discovered_ips - old_ips

			self.devices[device_mac]["ips"] = list(discovered_ips)
			self.devices[device_mac]["last_seen"] = datetime.now()

			if len(ips_to_add) > 0:
				for ip in ips_to_add:
					self.filter.tc_add_filter(\
											self.devices[device_mac]['token'],
											ip, self.devices[device_mac])
					self.active_filters += 2

			#if len(ips_to_delete) > 0 and self.filter_delete_counter > self.FILTER_DELETE_INTERVAL:
			#	for ip in ips_to_delete:
			#		self.filter.tc_del_filter(self.devices[device_mac]['token'], ip, self.devices[device_mac])
			#		self.active_filters -= 2
			#	self.filter_delete_counter = 0
			#else:
			#	self.filter_delete_counter += 1


	def print_devices(self):
		for device, obj in self.devices.items():
			print "\n"+device
			for name, value in obj.items():
				if name == "prefs":
					print "\t\t"+name+":"
					for x, v in value["lan"].items():
						print "\t\t\tlan\t", x, v
					for x, v in value["wan"].items():
						print "\t\t\twan\t", x, v
				else:
					print "\t\t"+name+":", value

	#Grabs device adresses
	def get_devices_adresses(self):

		proc    = subprocess.Popen('ip neigh show dev '+self.filter.LAN_INTERFACE,\
		 							shell=True, stdout=subprocess.PIPE)
		output  = proc.communicate()
		lines   = output[0].split('\n')
		clients = dict()

		for l in lines:
			var = l.split()

			if len(var) == 4:
				ip = var[0]
				mac = var[2]
				state = var[3]

				if ip[:6] == "fe80::":
					continue

				if not mac in clients.keys():
					clients[mac] = [ip]
				else:
					clients[mac].append(ip)
		return clients

	def get_devices_adresses_from_snmp(self):
		return self.SNMPDetector.get_adresses("2.4Ghz")

	def get_speed(self):
		proc    = subprocess.Popen('ifconfig '+self.filter.WAN_INTERFACE+\
									" | grep 'RX bytes'", shell=True,\
									stdout=subprocess.PIPE)
		output  = proc.communicate()
		line   = output[0].split('\n')[0]

		new_Down = int(line.split(':')[1].split()[0])
		new_Up = int(line.split(':')[2].split()[0])
		new_Time = datetime.now()

		interval = (new_Time-self.speed["Last_Update"]).total_seconds()
		down_Speed = round(((new_Down-self.speed["Down"])*8/interval)/1000000, 2)
		up_Speed = round(((new_Up-self.speed["Up"])*8/interval)/1000000, 2)

		self.speed = {	'Down'			: new_Down,
						'Up'			: new_Up,
						'Last_Update'	: new_Time
					}

		return " Down/Up: "+str(down_Speed) + "/" + str(up_Speed)+" Mbps"

##Executed if only is the main app
if __name__ == '__main__':

	def signal_handler(signal, frame):

		print '\nYou pressed Ctrl+C!'
		print '\n\t Stopping\t ...\n'
		sc.stop()
		#sc.print_devices()
		sys.exit(0)

	signal.signal(signal.SIGINT, signal_handler)


	sc = TShapper()
	sc.start()

	while True:
		sleep(2)
