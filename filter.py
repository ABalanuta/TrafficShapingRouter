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

    DEF_HTB_RATE		= "300Mbit"	#Rate of the def bucket
    USER_UP_RATE 		= "1050kbit"
    USER_UP_CEIL_RATE 	= "1200kbit"
    USER_DOWN_RATE 		= "4100Kbit"
    USER_DOWN_CEIL_RATE = "4400Kbit"

    wan_ip_prefs	= set()
    lan_ip_prefs	= set()

    def console(self, exe):
        #cprint("\t"+exe, 'cyan')
        logging.debug("\tIN: "+str(exe))

        proc = subprocess.Popen("nice -n10 "+exe, shell=True,\
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = proc.communicate()

        #cprint("\tOut: "+str(len(output))+":"+str(output), 'white')
        logging.debug(str(output))

        for x in output:
            if 'We have an error talking to the kernel' in x:
                raise KernelError(datetime.now())

            #if 'Device or resource busy' in x:
            #	raise DeviceError(exe)

    def destroy_tc_rules(self):
        cprint("Destroy TC Rules", 'red')
        logging.info('Destroy TC Rules')

        #Delete rules
        self.console('tc qdisc del dev '+self.WAN_INTERFACE+' root')
        self.console('tc qdisc del dev '+self.LAN_INTERFACE+' root')

    def init_tc_rules(self):
        cprint("Init TC Rules", 'red')
        logging.info('Init TC Rules')

        #Delete previous rules
        self.console('tc qdisc del dev '+self.WAN_INTERFACE+' root')
        self.console('tc qdisc del dev '+self.LAN_INTERFACE+' root')

        self.console('tc qdisc add dev '+self.WAN_INTERFACE+\
                     ' root handle 1:0 htb default FFFF')
        self.console('tc class add dev '+self.WAN_INTERFACE+\
                     ' parent 1:0 classid 1:FFFF htb rate '+self.DEF_HTB_RATE+\
                     ' ceil '+self.DEF_HTB_RATE+' prio 0')

        self.console('tc qdisc add dev '+self.LAN_INTERFACE+\
                     ' root handle 1:0 htb default FFFF')
        self.console('tc class add dev '+self.LAN_INTERFACE+\
                     ' parent 1:0 classid 1:FFFF htb rate '+self.DEF_HTB_RATE+\
                     ' ceil '+self.DEF_HTB_RATE+' prio 0')

    #Creates a new TC Filter Rule
    def tc_add_device(self, obj):
        cprint("Add Device: "+obj["mac"], 'yellow')
        logging.info("Add Device: "+obj["mac"])

        self.console('tc class add dev '+self.LAN_INTERFACE+\
                     ' parent 1:0 classid 1:'+str(obj['token'])+\
                     ' htb rate '+self.USER_DOWN_RATE+' ceil '+\
                     self.USER_DOWN_CEIL_RATE+' prio 1')

        self.console('tc class add dev '+self.WAN_INTERFACE+\
                     ' parent 1:0 classid 1:'+str(obj['token'])+\
                     ' htb rate '+self.USER_UP_RATE+' ceil '+\
                     self.USER_UP_CEIL_RATE+' prio 1')

    def tc_add_filter(self, token, ip, obj):
        #IPv6
        if ':' in ip:
            self.tc_add_filter_IPv6(token, ip, obj)
        #IPv4
        elif '.' in ip:
            self.tc_add_filter_IPv4(token, ip, obj)

    def tc_add_filter_IPv4(self, token, ip, obj):
        cprint("\t Add IPv4 Filter: "+ip+" for "+obj["mac"], 'yellow')
        logging.info("\t Add IPv4 Filter: "+ip+" for "+obj["mac"])

        self.console('tc filter add dev '+self.LAN_INTERFACE+\
                     ' protocol ip parent 1:0 prio 0 u32 match ip dst '+ip+\
                     ' flowid 1:'+str(token))
        pref = self.tc_get_new_filter_pref(self.LAN_INTERFACE)
        obj["prefs"]["lan"][ip] = pref
        self.lan_ip_prefs |= pref

        self.console('tc filter add dev '+self.WAN_INTERFACE+\
                     ' protocol ip parent 1:0 prio 0 u32 match ip src '+ip+\
                     ' flowid 1:'+str(token))
        pref = self.tc_get_new_filter_pref(self.WAN_INTERFACE)
        obj["prefs"]["wan"][ip] = pref
        self.wan_ip_prefs |= pref

    def tc_add_filter_IPv6(self, token, ip, obj):
        cprint("\t Add IPv6 Filter: "+ip+" for "+obj["mac"], 'yellow')
        logging.info("\t Add IPv6 Filter: "+ip+" for "+obj["mac"])

        self.console('tc filter add dev '+self.LAN_INTERFACE+\
                     ' protocol ipv6 parent 1:0 prio 0 u32 match ip6 dst '+ip+\
                     ' flowid 1:'+str(token))
        pref = self.tc_get_new_filter_pref(self.LAN_INTERFACE)
        obj["prefs"]["lan"][ip] = pref
        self.lan_ip_prefs |= pref
        logging.debug("\t new Filter LAN Pref: "+ str(pref))

        self.console('tc filter add dev '+self.WAN_INTERFACE+\
                     ' protocol ipv6 parent 1:0 prio 0 u32 match ip6 src '+ip+\
                     ' flowid 1:'+str(token))
        pref = self.tc_get_new_filter_pref(self.WAN_INTERFACE)
        obj["prefs"]["wan"][ip] = pref
        self.wan_ip_prefs |= pref
        logging.debug("\t new Filter WAN Pref: "+ str(pref))

    def tc_del_filter(self, token, ip, obj):

        cprint("\t Del Filter: "+ip+" for "+obj["mac"], 'yellow')
        logging.info("\t Del Filter: "+ip+" for "+obj["mac"])

        #Delete LAN filters
        for pref in obj["prefs"]["lan"][ip]:
            self.console('tc filter del dev '+self.LAN_INTERFACE+' pref '+pref)
            logging.debug("\t delete Filter LAN Pref: "+ str(pref))

        self.lan_ip_prefs = self.lan_ip_prefs - obj["prefs"]["lan"][ip]
        del obj["prefs"]["lan"][ip]

        #Delete WAN filters
        for pref in obj["prefs"]["wan"][ip]:
            self.console('tc filter del dev '+self.WAN_INTERFACE+' pref '+pref)
            logging.debug("\t delete Filter WAN Pref: "+ str(pref))

        self.wan_ip_prefs = self.wan_ip_prefs - obj["prefs"]["wan"][ip]
        del obj["prefs"]["wan"][ip]

    #Returns the id of the filter
    def tc_get_new_filter_pref(self, interface):
        prefs   = set()
        proc    = subprocess.Popen('tc -p filter list dev '+interface+\
                                   ' parent 1:0', shell=True,\
                                   stdout=subprocess.PIPE)
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
        self.console('tc class del dev '+self.LAN_INTERFACE+\
                     ' parent 1:0 classid 1:'+str(token))
        self.console('tc class del dev '+self.WAN_INTERFACE+\
                     ' parent 1:0 classid 1:'+str(token))
