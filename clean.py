import subprocess

LAN_INTERFACE	= "eth0"
WAN_INTERFACE 	= "eth1"


def console(exe):
	proc = subprocess.Popen("nice -n10 "+exe, shell=True,\
							stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	output = proc.communicate()

def destroy_tc_rules():

	console('tc qdisc del dev '+WAN_INTERFACE+' root')
	console('tc qdisc del dev '+LAN_INTERFACE+' root')

##Executed if only is the main app
if __name__ == '__main__':

	destroy_tc_rules()
