#!/usr/bin/env python

#	Licensed under the GPL V2
#	Alain <ozwald> Schneider - COGICEO 2014

import serial
import os

class controller:
	def __init__(self, port='/dev/ttyACM0', speed=115200):
		self.ser = serial.Serial(port, speed, timeout=5, stopbits = serial.STOPBITS_ONE, parity = serial.PARITY_NONE)
		self.ser.flushInput()
	def set_channel(self, channel):
		self.ser.write(chr(30)) 
		self.ser.write(chr(channel))
		self.ser.flush()
	def read_channel(self):
		self.ser.write(chr(40))
		channel = self.ser.read(1)
		if channel:
			return ord(channel)
	def read_packet(self):
		self.ser.write(chr(50))
		self.ser.flush()
		available = self.ser.read(1)
		if available==chr(1):
			packet = self.ser.read(32)
			return packet
		return None
	def set_addr(self, addr):
		self.ser.write(chr(60))
		self.ser.write(chr(len(addr)))
		for octet in addr:
			self.ser.write(chr(octet))
			ack = self.ser.read(1)
			if ord(ack)!=octet:
				print "WTF ?!", ord(ack), octet
	def autotune(self, delay=10, threshold = 2, max_channel=127, min_channel=0, start_channel=None, forced_addr=None, step=2):
		"""
		Tune to a frequency, sniff for a while and note the seen address.
		if no address repeats more than "threshold" during "delay" : skip to next channel

		NB : this function never ends :D...
		"""
		if min_channel==max_channel:
			print("WARNING : known bug if min_channel==max_channel, sniffing may not work, you should set min_channel lower by one...Now you've been warned :D")
			# I don't know the reason, might be addr setting delay, or fifo purging, or whatever... :)

		channel = None
		while channel==None:
			channel = self.read_channel()

		import time
		stop=False
		if forced_addr==None:
			my_addrs = [ [0xAA, 0x00], [0x55, 0x00] ]
		else:
			my_addrs = [forced_addr]
		my_addr = my_addrs[0]
		print("Switching to addr : %s"%''.join([hex(O)[2:].zfill(2) for O in my_addr]))
		self.set_addr(my_addr)

		if start_channel!=None:
			channel = start_channel-step

		while stop==False:
			channel+=step
			if channel<min_channel:
				channel = min_channel
			if channel>max_channel:
				channel = min_channel
				if my_addr == my_addrs[0]:
					my_addr = my_addrs[-1]
				else:
					my_addr = my_addrs[0]
				print("Switching to addr : %s"%''.join([hex(O)[2:].zfill(2) for O in my_addr]))
				self.set_addr(my_addr)

			while self.read_channel()!=channel:
				self.set_channel(channel)
				time.sleep(0.2)

			print "Tuned to channel %d, listenning for address."%channel
			addrs = []
			start = time.time()
			while time.time() - start < delay:
				p = self.read_packet()
				if p:
					addrs += addr_guesser(p, use_heuristic=(forced_addr==None))
			
			printed = []
			for a in addrs:
				if (addrs.count(a) >= threshold) and not (a in printed):
					print "\t",["%02X"%ord(octet) for octet in a],"appeared",addrs.count(a),"times"
					printed.append(a)
			if forced_addr!=None and len(addrs)>0:
				print("\tbut you specified an address, and I still received %d packets with this tuning"%(len(addrs)))

def addr_guesser(packet, addr_len=5, use_heuristic=True):
	"""
	Take a packet (32 char string), and return a list of potential address within it
	"""
	potential_addr = packet[0:5]
	if use_heuristic==True and ( potential_addr.count(chr(0x55))>2 or potential_addr.count(chr(0xAA))>2 ):
		return [] # little heuristic to suppress some noise.

	return [potential_addr]

ALREADY_PRINTED = []
class nrf24_packet():
	"""
	Those packet should not contain the adresse; i.e. it should not be used in promisc mode.
	"""
	def __init__(self,packet, addr):
		self.addr = addr
		self.packet = packet #from a controller.read_packet() - This SHOULD NOT contain the address :)
		
		self.bits = []
		for B in self.packet:
			self.bits+= [int(b) for b in bin(ord(B))[2:].zfill(8)]
		self.nrfheader = self.bits[:9]
		self.nrfpayload_bits = self.bits[9:]
	def parse_me(self):
		searched = bin(0x0A)[2:].zfill(8)
		searched+= bin(0x78)[2:].zfill(8)
		bits = "".join([str(b) for b in self.bits])
		if searched in bits:
			seq = bits[bits.find(searched)+len(searched)+2*8: bits.find(searched)+len(searched)+2*8 +8]
			seq = int(seq,2)
			if seq in ALREADY_PRINTED:
				return
			#ALREADY_PRINTED.append(seq)

			hid = bits[bits.find(searched)+len(searched)+7*8: bits.find(searched)+len(searched)+7*8 +8]
			hid = int(hid,2)
			hid = hid^self.addr[0]
			if hid>=0x04 and hid<=0x28:
				print '\033[94m%02X\033[0m'%hid,
				if hid <= 0x1D:
					print chr(ord('a')+hid-0x04)
				else:
					print '#'
			else:
				print '?'
			return True
		else:
			print bits[:9],
			for o in range(16):
				print bits[9+o*8:9+(o+1)*8],
			print '...'
			return False

def bench(c):
	"""
	Benchmark.
	Sniff in a loop for 10s and returns the number of packets read during that 1s laps.
	"""
	import time
	packet_nb = 0
	start = time.time()
	while time.time()-start<10.0:
		packet= c.read_packet()
		if packet:
			packet_nb+=1
	return packet_nb


if __name__=='__main__':
	import argparse

	parser = argparse.ArgumentParser(description='NRF24 sniffer using serial communication with an arduino.')

	parser.add_argument('--serial','-s', help="Serial device to use (default:'/dev/ttyACM0')", default='/dev/ttyACM0')
	
	promisc = parser.add_argument_group('Promiscuous')
	promisc.add_argument("--promisc", "-p", help="Sniff the air in search for valid NRF24 address",action="store_true")
	promisc.add_argument("--channel-min", help="Smallest channel to promiscuously sniff (default : 0)", type=int, default=0)
	promisc.add_argument("--channel-max", help="Biggest channel to promiscuously sniff (default : 127)", type=int, default=127)
	promisc.add_argument("--channel-start", help="Starting channel for promiscuously sniff (default : last used)", default=None)
	promisc.add_argument("--channel-step", help="Steping channel for promiscuously sniff (default : 2)", default=2, type=int)
	promisc.add_argument("--delay", '-d', help="Promiscuously sniff each channel for so much seconds (default : 10)", type=int, default=10)
	promisc.add_argument("--threshold", '-t', help="Consider an address valid if counted more than this (default : 2)", type=int, default=2)

	sniffing = parser.add_argument_group('Targeted sniff')
	sniffing.add_argument("-c",'--channel',help='Channel to tune to (default:1)', type=int, default=1)
	sniffing.add_argument("-a",'--addr', help="Address to sniff (in hexa form : AABBCCDDEE)", default=None)
	sniffing.add_argument("-r",'--reverse', help="Reverse the adress byte order", default=False, action="store_true")
	sniffing.add_argument("-b",'--bench', help="Only benchmark this channel/addr combination for 10s",action="store_true")
	sniffing.add_argument("-M",'--Microsoft', help="Try to decypher Microsoft keyboard \"encryption\"",action="store_true")

	args = parser.parse_args()

	c = controller(port=args.serial)

	if args.promisc:
		print("Starting to sniff in promiscuous mode")

		addr = None
		if args.addr!=None :
			addr = []
			for i in range(0,len(args.addr),2):
				addr.append( int(args.addr[i:i+2],16) )
			if args.reverse==True:
				addr = addr[::-1] #Yeah, join the endianness insanity party :-D !
			print("Setting targeted adress to : "+''.join([hex(O)[2:].zfill(2) for O in addr]))
		start = None
		if args.channel_start!=None:
			start = int(args.channel_start)
		c.autotune(delay=args.delay, threshold=args.threshold, max_channel=args.channel_max , min_channel=args.channel_min, forced_addr=addr, start_channel = start, step=args.channel_step)
	else:
		import re, sys
		if (args.addr==None) or (not re.match("^[a-fA-F0-9]+$",args.addr)) or (not len(args.addr) in [4,6,8,10]) :
			print("Fatal : you MUST specify a valid adress (-a) for non-promiscuous sniffing")
			sys.exit(1)

		print("Setting channel to : %d"%args.channel)
		while c.read_channel()!=args.channel:
			c.set_channel(args.channel)
			import time
			time.sleep(0.5)
		print("\tOK")


		addr = []
		for i in range(0,len(args.addr),2):
			addr.append( int(args.addr[i:i+2],16) )
		if args.reverse==True:
			addr = addr[::-1] #Yeah, join the endianness insanity party :-D !
		print("Setting targeted adress to : "+''.join([hex(O)[2:].zfill(2) for O in addr]))
		c.set_addr(addr)
		print("\tOK")


		if args.bench==True:
			print("Benchmarking this configuration for 10s")
			nb_packets = bench(c)
			print("During 10s, this configuration (channel/addr) received %d packets"%nb_packets)
			sys.exit(0)

		print("Starting to sniff forever.")
		while True:
			tmp = c.read_packet()
			if tmp:
				if args.Microsoft==True:
					n = nrf24_packet(tmp, addr)
					if n.parse_me()==False:
						print ( "".join(['%02X'%ord(octet) for octet in tmp]) )
				else:
					print ( "".join(['%02X'%ord(octet) for octet in tmp]) )
					
