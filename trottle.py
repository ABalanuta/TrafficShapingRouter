#!/usr/bin/python

import sys
import signal
import subprocess
import logging
from time import sleep
from threading import Thread
from datetime import datetime
from termcolor import colored, cprint

class Filter():

	LAN_INTERFACE	= "eth0"
	WAN_INTERFACE 	= "eth1"

	DEF_HTB_RATE	= "100Mbit"	#Rate of the def bucket
	USER_UP_RATE 	= "2048kbit"	
	USER_DOWN_RATE 	= "5240Kbit"

	wan_ip_prefs	= set()
	lan_ip_prefs	= set()

	def console(self, exe):
		cprint("\t"+exe, 'cyan')
		#logging.debug("\t"+exe)
		proc    = subprocess.Popen("nice -n10 "+exe, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                output  = proc.communicate()
		cprint("\tOut: "+str(len(output))+":"+str(output), 'white')
	def destroy_tc_rules(self):
		cprint("Destroy TC Rules", 'red')

		#Delete rules
		self.console('tc qdisc del dev '+self.WAN_INTERFACE+' root')
		self.console('tc qdisc del dev '+self.LAN_INTERFACE+' root')

	def init_tc_rules(self):
		
		#Delete previous rules
		self.console('tc qdisc del dev '+self.WAN_INTERFACE+' root')
		self.console('tc qdisc del dev '+self.LAN_INTERFACE+' root')

		self.console('tc qdisc add dev '+self.WAN_INTERFACE+' root handle 1:0 htb default FFFF')
		self.console('tc class add dev '+self.WAN_INTERFACE+' parent 1:0 classid 1:FFFF htb rate '+self.DEF_HTB_RATE+' ceil '+self.DEF_HTB_RATE+' prio 0')

		self.console('tc qdisc add dev '+self.LAN_INTERFACE+' root handle 1:0 htb default FFFF')
		self.console('tc class add dev '+self.LAN_INTERFACE+' parent 1:0 classid 1:FFFF htb rate '+self.DEF_HTB_RATE+' ceil '+self.DEF_HTB_RATE+' prio 0')

	#Creates a new TC Filter Rule
	def tc_add_device(self, obj):
		cprint("Add Device: "+obj["mac"], 'yellow')
		self.console('tc class add dev '+self.LAN_INTERFACE+' parent 1:0 classid 1:'+str(obj['token'])+' htb rate '+self.USER_DOWN_RATE+' ceil '+self.USER_DOWN_RATE+' prio 0')
		self.console('tc class add dev '+self.WAN_INTERFACE+' parent 1:0 classid 1:'+str(obj['token'])+' htb rate '+self.USER_UP_RATE+' ceil '+self.USER_UP_RATE+' prio 0')

	def tc_add_filter(self, token, ip, obj):
		#IPv6
		if ':' in ip:
			self.tc_add_filter_IPv6(token, ip, obj)
		#IPv4
		elif '.' in ip:
			self.tc_add_filter_IPv4(token, ip, obj)
			
	def tc_add_filter_IPv4(self, token, ip, obj):
		cprint("\t Add IPv4 Filter: "+ip+" for "+obj["mac"], 'yellow')
		self.console('tc filter add dev '+self.LAN_INTERFACE+' protocol ip parent 1:0 prio 0 u32 match ip dst '+ip+' flowid 1:'+str(token))
		pref = self.tc_get_new_filter_pref(self.LAN_INTERFACE)
		obj["prefs"]["lan"][ip] = pref
		self.lan_ip_prefs |= pref

		self.console('tc filter add dev '+self.WAN_INTERFACE+' protocol ip parent 1:0 prio 0 u32 match ip src '+ip+' flowid 1:'+str(token))
		pref = self.tc_get_new_filter_pref(self.WAN_INTERFACE)
		obj["prefs"]["wan"][ip] = pref
		self.wan_ip_prefs |= pref

	def tc_add_filter_IPv6(self, token, ip, obj):
		cprint("\t Add IPv6 Filter: "+ip+" for "+obj["mac"], 'yellow')
		self.console('tc filter add dev '+self.LAN_INTERFACE+' protocol ipv6 parent 1:0 prio 0 u32 match ip6 dst '+ip+' flowid 1:'+str(token))
		pref = self.tc_get_new_filter_pref(self.LAN_INTERFACE)
		obj["prefs"]["lan"][ip] = pref
		self.lan_ip_prefs |= pref

		self.console('tc filter add dev '+self.WAN_INTERFACE+' protocol ipv6 parent 1:0 prio 0 u32 match ip6 src '+ip+' flowid 1:'+str(token))
		pref = self.tc_get_new_filter_pref(self.WAN_INTERFACE)
		obj["prefs"]["wan"][ip] = pref
		self.wan_ip_prefs |= pref

	def tc_del_filter(self, token, ip, obj):

		cprint("\t Del Filter: "+ip+" for "+obj["mac"], 'yellow')

		#Delete LAN filters
		for pref in obj["prefs"]["lan"][ip]:
			self.console('tc filter del dev '+self.LAN_INTERFACE+' pref '+pref)
		self.lan_ip_prefs = self.lan_ip_prefs - obj["prefs"]["lan"][ip]
		del obj["prefs"]["lan"][ip]

		#Delete WAN filters
		for pref in obj["prefs"]["wan"][ip]:
			self.console('tc filter del dev '+self.WAN_INTERFACE+' pref '+pref)
		self.wan_ip_prefs = self.wan_ip_prefs - obj["prefs"]["wan"][ip]
		del obj["prefs"]["wan"][ip]

	#Returns the id of the filter
	def tc_get_new_filter_pref(self, interface):
		prefs   = set()
		proc    = subprocess.Popen('tc -p filter list dev '+interface+' parent 1:0', shell=True, stdout=subprocess.PIPE)
		output  = proc.communicate()
		lines   = output[0].split('\n')
		for line in lines:
			if 'pref' in line:
				words = line.split()
				pref = words[words.index('pref')+1]
				prefs = prefs | set([pref])

		if interface == self.WAN_INTERFACE:
			return prefs - self.wan_ip_prefs

		elif interface == self.LAN_INTERFACE:
			return prefs - self.lan_ip_prefs

	def tc_del_class(self, token, obj):
		cprint("Delete Client: "+obj['mac'], 'red')
		self.console('tc class del dev '+self.LAN_INTERFACE+' parent 1:0 classid 1:'+str(token))
		self.console('tc class del dev '+self.WAN_INTERFACE+' parent 1:0 classid 1:'+str(token))

class TShapper(Thread):

	N_TOKENS        		= 9000
	TOKENS 				= list()
	DEVICES 			= dict()
	MAX_DEVICES 			= {
						'Number': 0,
						'Time'  : datetime.now()
					}

	SLEEP_INTERVAL  	= 0.1		#Seconds
	OLD_DEVICES_TIMEOUT 	= 60 		#Seconds

	def __init__(self):
		Thread.__init__(self)
		logging.basicConfig(filename='trottle.log',level=logging.DEBUG)
		logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
		self.stopped = False
		self.active_filters = 0
		self.speed = {	'Down'		: 0,
				'Up'		: 0,
				'Last_Update'	: datetime.now()
				}

		self.filter = Filter()
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
		
		#Deletes the TC Rules
		self.filter.destroy_tc_rules()


	def run(self):

		#Starts the new TC Rules
		self.filter.init_tc_rules()

		#Updates the TC Rules
		while not self.stopped:
			self.update()
			sleep(self.SLEEP_INTERVAL)

	def update(self):
		#cprint("Update", 'white')
		
		updated_devices = self.get_devices_adresses()

		for device_mac, ips in updated_devices.items():
			self.update_device(device_mac, ips)

		self.clean_old_devices()

		if len(self.DEVICES) > self.MAX_DEVICES['Number']:
			self.MAX_DEVICES['Number'] = len(self.DEVICES)
			self.MAX_DEVICES['Time'] = datetime.now()

		cprint("Current Clients/Max:"+str(len(self.DEVICES))+"/"+str(self.MAX_DEVICES['Number'])+" at "+str(self.MAX_DEVICES['Time'])+" TokensLeft:"+str(len(self.TOKENS))+" ActiveFilters:"+str(self.active_filters)+self.get_speed(), 'green')


	def clean_old_devices(self):
		for device_mac, obj in self.DEVICES.items():
			if (datetime.now() - obj["last_seen"]).total_seconds() > self.OLD_DEVICES_TIMEOUT:
				obj = self.DEVICES[device_mac]
				token = obj["token"]

				#Delete Filters
				for ip in obj["ips"]:
					self.filter.tc_del_filter(token, ip, obj)
					self.active_filters -= 2

				#Delete Class
				self.filter.tc_del_class(token, obj)

				del self.DEVICES[device_mac]
				self.release_token(token)
				

	def update_device(self, device_mac, ips):
		
		#Add new Device
		if device_mac not in self.DEVICES.keys():
			obj	  = { 	"mac":device_mac,
						"token":self.get_token(),
						"ips":ips,
						"last_seen":datetime.now(),
						"prefs": {
									"lan": dict(),
									"wan": dict()
								}
					}
			self.DEVICES[device_mac] = obj

			self.filter.tc_add_device(obj)

			for ip in ips:
				self.filter.tc_add_filter(obj['token'], ip, obj)
				self.active_filters += 2

		#Modify Existing Device Rules
		else:
			old_ips = set(self.DEVICES[device_mac]["ips"])
			discovered_ips = set(ips)
			ips_to_delete = old_ips - discovered_ips
			ips_to_add = discovered_ips - old_ips

			self.DEVICES[device_mac]["ips"] = list(discovered_ips)
			self.DEVICES[device_mac]["last_seen"] = datetime.now()

			if len(ips_to_add) > 0:
				for ip in ips_to_add:
					self.filter.tc_add_filter(self.DEVICES[device_mac]['token'], ip, self.DEVICES[device_mac])
					self.active_filters += 2

			if len(ips_to_delete) > 0:
				for ip in ips_to_delete:
					self.filter.tc_del_filter(self.DEVICES[device_mac]['token'], ip, self.DEVICES[device_mac])
					self.active_filters -= 2

	def print_devices(self):
		for device, obj in self.DEVICES.items():
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
		
		proc    = subprocess.Popen('ip neigh show dev '+self.filter.LAN_INTERFACE, shell=True, stdout=subprocess.PIPE)
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


	def get_speed(self):
		proc    = subprocess.Popen('ifconfig '+self.filter.WAN_INTERFACE+" | grep 'RX bytes'", shell=True, stdout=subprocess.PIPE)
		output  = proc.communicate()
		line   = output[0].split('\n')[0]
		
		new_Down = int(line.split(':')[1].split()[0])
		new_Up = int(line.split(':')[2].split()[0])
		new_Time = datetime.now()

		interval = (new_Time-self.speed["Last_Update"]).total_seconds()
		down_Speed = round(((new_Down-self.speed["Down"])*8/interval)/1000000, 2) 	#Mbits/s
		up_Speed = round(((new_Up-self.speed["Up"])*8/interval)/1000000, 2) 			#Mbits/s

		self.speed = {	'Down'			: new_Down,
						'Up'			: new_Up,
						'Last_Update'	: new_Time
					}

		return " Down/Up: "+str(down_Speed) + "/" + str(up_Speed)+" Mbps"	

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
