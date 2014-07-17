#!/usr/bin/python

import sys
import signal
import subprocess
from time import sleep
from threading import Thread
from datetime import datetime


class TShapper(Thread):

	LAN_INTERFACE 			= "eth0"
	WAN_INTERFACE 			= "eth1"

	N_TOKENS        		= 3000
	TOKENS 					= list()
	DEVICES 				= dict()

	SLEEP_INTERVAL  		= 0.75		#Seconds
	OLD_DEVICES_TIMEOUT 	= 3 	#Seconds

	DEF_HTB_RATE			= "8Mbit"
	USER_HTB_RATE			= "100Mbit"


	def __init__(self):
		Thread.__init__(self)
		self.stopped = False
		self.generate_tokens()


	def generate_tokens(self):
		for i in range(1, self.N_TOKENS+1):
			self.TOKENS.append(i)

	def get_token(self):
		return self.TOKENS.pop(0)

	def release_token(self, token):
		self.TOKENS.append(token)

	def stop(self):
		self.stopped = True

	def run(self):

		#Starts the new TC Rules
		self.init_tc_rules()

		#Modifies the TC Rules
		while not self.stopped:
			self.update()
			sleep(self.SLEEP_INTERVAL)

		#Deletes the TC Rules
		self.destroy_tc_rules()

	def update(self):
		print "Update"
		
		updated_devices = self.get_devices_adresses()

		for device_mac, ips in updated_devices.items():
			self.update_device(device_mac, ips)

		self.clean_old_devices()

		print "Clients:"+str(len(self.DEVICES))+" TokensLeft:"+str(len(self.TOKENS))

	def destroy_tc_rules(self):
		pass

	def init_tc_rules(self):
		cmd = 'tc qdisc del dev '+self.LAN_INTERFACE+' root'
		print cmd 
		subprocess.call(cmd, shell=True)

		cmd = 'tc qdisc del dev '+self.WAN_INTERFACE+' root'
		print cmd 
		subprocess.call(cmd, shell=True)

		cmd = 'tc qdisc add dev '+self.LAN_INTERFACE+' root handle 1:0 htb default FFFF'
		print cmd 
		subprocess.call(cmd, shell=True)

		cmd = 'tc qdisc add dev '+self.WAN_INTERFACE+' root handle 1:0 htb default FFFF'
		print cmd 
		subprocess.call(cmd, shell=True)

		cmd = 'tc class add dev '+self.LAN_INTERFACE+' 1:0 classid 1:FFFF htb rate '+self.DEF_HTB_RATE+' ceil '+self.DEF_HTB_RATE+' prio 0'
		print cmd 
		subprocess.call(cmd, shell=True)

		cmd = 'tc class add dev '+self.WAN_INTERFACE+' 1:0 classid 1:FFFF htb rate '+self.DEF_HTB_RATE+' ceil '+self.DEF_HTB_RATE+' prio 0'
		print cmd 
		subprocess.call(cmd, shell=True)
        


	def clean_old_devices(self):
		for device_mac, obj in self.DEVICES.items():
			if (datetime.now() - obj["last_seen"]).total_seconds() > self.OLD_DEVICES_TIMEOUT:
				print "Delete Client: "+device_mac
				token = self.DEVICES[device_mac]["token"]
				del self.DEVICES[device_mac]
				self.release_token(token)

	def update_device(self, device_mac, ips):
		
		#Add new Device
		if device_mac not in self.DEVICES.keys():
			token = self.get_token()
			obj	  = { 	"token":token,
						"ips":ips,
						"last_seen":datetime.now()
					}
			self.DEVICES[device_mac] = obj
			self.update_rules(device_mac, obj)

		#Modify Existing Device Rules
		else:
			old_ips = set(self.DEVICES[device_mac]["ips"])
			discovered_ips = set(ips)
			ips_to_delete = old_ips - discovered_ips
			ips_to_add = discovered_ips - old_ips

			self.DEVICES[device_mac]["ips"] = list(discovered_ips)
			self.DEVICES[device_mac]["last_seen"] = datetime.now()

			if len(ips_to_add) > 0:
				print "New IPs "+str(ips_to_add)+" for MAC "+device_mac

			if len(ips_to_delete) > 0:
				print "Delete IPs "+str(ips_to_delete)+" for MAC "+device_mac

			#self.update_rules_add(device_mac, ips_to_add)
			#self.update_rules_del(device_mac, ips_to_delete)

	def update_rules(self, device_mac, ips):
		pass

	def print_devices(self):
		for device, obj in self.DEVICES.items():
			print device, obj

	def get_devices_adresses(self):
		
		proc = subprocess.Popen('ip neigh show dev '+self.LAN_INTERFACE, shell=True, stdout=subprocess.PIPE)
		output = proc.communicate()
		lines = output[0].split('\n')

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


##Executed if only is the main app
if __name__ == '__main__':

	#if len(sys.argv) < 2:
	#	print "usage: "
	#	print "       "+str(sys.argv[0])+" start #Starts"
	#	print "       "+str(sys.argv[0])+" stop "

	def signal_handler(signal, frame):

		print '\nYou pressed Ctrl+C!'
		print '\n\t Stopping\t ...\n'
		sc.stop()
		sc.print_devices()
		sys.exit(0)

	signal.signal(signal.SIGINT, signal_handler)


	sc = TShapper()
	sc.start()

	while True:
		sleep(2)


#for x, v in get_ipv6_connections()[1].items():
#	print TOKENS.pop(0), x, v
