import sys
import random
from scapy.all import *

import netaddr


if sys.argv[0] != 1 :
	print "usage this.py 192.168.1.0/29"

#define the target
#net_target = sys.argv[1] 
net_target = "192.168.1.0/29"

#define port rangej
portRange = [22,23,80,443,3389,8080]



net = netaddr.IPNetwork(net_target)

count = 0 

#portscan function
def portScan(ip_target, ports):
	for dstPort in portRange:

		srcPort = random.randint(1025,65534)
		srcS = TCP(sport=srcPort, dport=dstPort,flags="S")
		res = sr1(ip/srcS,timeout=1,verbose=0)

		if (str(type(res))=="<type 'NoneType'>"):
			print ip_target + ":" + str(dstPort) + " => filtered"
		elif(res.haslayer(ICMP)):
			if(int(res.getLayer(ICMP).type)==3 and int(res.getlayer(ICMP).code) in [1,2,3,9,10,13]):
				print ip_target + ":" + str(dstPort) + " => filtered"
		elif(res.haslayer(TCP)):
			if(res.getlayer(TCP).flags == 0x12):
				srcS = TCP(sport=srcPort, dport=dstPort,flags="S")
				send_rst=sr(ip/srcS,timeout=1,verbose=0)
				print ip_target + ":" + str(dstPort) + " => open"
			elif(res.getlayer(TCP).flags == 0x14):
				print ip_target + ":" + str(dstPort) + " => closed"


for host in net:
	if (host == net.network or host == net.broadcast):
		continue
	ip = IP()
	ip.dst = str(host)
	res = sr1(ip/ICMP(),timeout=2,verbose=0)
	if(str(type(res))=="<type 'NoneType'>"):
		print str(host)+" => down or not responding"
	elif(int(res.getlayer(ICMP).type)==3 and int(res.getlayer(ICMP).code) in [1,2,3,9,10,13]):
		print str(host)+" => blocking ICMP"
	else:
		portScan(str(host),portRange)
		count+=1
		

print "out of" + str(net.size) +" hosts," + str(count)+" are online"
