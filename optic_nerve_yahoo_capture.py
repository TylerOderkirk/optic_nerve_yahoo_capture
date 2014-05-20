#!/usr/bin/env python

DESC='''
Extracts JPEG 2000 Yahoo Messenger webcam images from given pcap file 
or given network interface and writes them to the current directory as 
PNG images named in this form: PKTNUM-SRCIP-DSTIP-YYYYMMDD-HHMMSS.png
where PKTNUM is the packet number from the capture/interface, SRCIP is
the source IP address, DSTIP is the destination IP address, and 
YYYYMMDD-HHMMSS is the time and date the image was captured.'''

# python-dpkt 1.6+svn54-1 (or dpkt 1.7 windows exe installer)
# glymur 0.5.10 (via pip)
#  libopenjpeg2:amd64 1.3+dfsg-4.6ubuntu2 (or openjpeg 2.0.0 windows)
#  python-numpy1:1.7.1-1ubuntu1 (numpy 1.1.1 windows)
# python-wand 0.3.7 (via pip)
#  libmagickwand58:6.7.7.10-5ubuntu3.1 (imagemagick 6.8.9 Q16 windows)
# python-pcapy 0.10.8-1build1 (pcapy 0.10.5 py2.7 winpcap 4.1.2 windows from breakingcode.wordpress.com)

import dpkt, socket, sys, tempfile, os, glymur, time, argparse 
from wand.image import Image

YMSGR_CAM_SOURCE_PORT = 5100
JP2K_CODESTREAM_MAGIC = "\xff\x4f\xff\x51"
JP2K_CODESTREAM_END = "\x80\x80\xff\xd9"

codestreams = {}

def parse_args():
	parser = argparse.ArgumentParser(description=DESC)
	group_input = parser.add_argument_group("Input")
	group = group_input.add_mutually_exclusive_group(required=True)
	group.add_argument("-i", action="store", dest="network_interface", help="Network interface to sniff packets from (e.g. 'wlan0')")
	group.add_argument("-f", action="store", dest="pcapfile", help="PCAP file to read packets from (e.g. 'foo.pcap')")
	args = parser.parse_args()
	return args

def process_packet(pkt_num, timestamp, buf):
	#print pkt_num, timestamp
	eth = dpkt.ethernet.Ethernet(buf)
	#print "eth.get_type(eth.type):", eth.get_type(eth.type)
	if eth.get_type(eth.type) != dpkt.ip.IP:
		return
	ip = eth.data
	#print "type(ip):", type(ip)
	if type(ip) == str:
		print "windows wierdness"
		return
	if ip.p != dpkt.ip.IP_PROTO_TCP:
		return
	tcp = ip.data
	src_ip = socket.inet_ntoa(ip.src)		
	dst_ip = socket.inet_ntoa(ip.dst)		

	# if it's coming from the port that yahoo messenger uses for webcam images and contains data...
	if tcp.sport == YMSGR_CAM_SOURCE_PORT and len(tcp.data) > 0:
		print "encountered potential yahoo messenger webcam feed data in packet number", pkt_num
		print " pkt_timestamp:", timestamp, "pkt_src:", socket.inet_ntoa(ip.src), "pkt_dst:", socket.inet_ntoa(ip.dst)
		print " data:", ':'.join(x.encode('hex') for x in tcp.data)[:59], "+[...]"
		# if it's the beginning of a new codestream...
		if tcp.data[:len(JP2K_CODESTREAM_MAGIC)]==JP2K_CODESTREAM_MAGIC: # TODO: startswith
			print " encountered beginning of new codestream"
			# if there was a previous codestream...
			if src_ip + "->" + dst_ip in codestreams:
				if codestreams[src_ip + "->" + dst_ip][-4:] != JP2K_CODESTREAM_END: # TODO: endswith
					print " warning: didn't see magic end-bytes"
				# write previous codestream to disk b/c glymur can't read from strings (a bug?)
				tf = tempfile.NamedTemporaryFile(delete=False,suffix='.jpc')  
				tf.write(codestreams[src_ip + "->" + dst_ip])
				print " writing previous codestream (size", len(codestreams[src_ip + "->" + dst_ip]), ") to", tf.name
				tf.close()

				# wrap previous codestream and write result to disk
				tf2 = tempfile.NamedTemporaryFile(delete=False,suffix='.jp2')  
				print " wrapping previous codestream and writing it to", tf2.name
				tf2.close()

				j2k = glymur.Jp2k(tf.name)
				jp2 = j2k.wrap(tf2.name)


				# convert jp2->png and save to disk
				with Image(filename=tf2.name) as img: # can pass blob=b
					img.format='png'
					formatted_timestamp = time.strftime('%Y%m%d_%H%M%S', time.localtime(timestamp))
					fn=str(pkt_num)+"-"+src_ip+"-"+dst_ip+"-"+formatted_timestamp+".png"
					print " writing PNG to", fn
					img.save(filename=fn)

				os.unlink(tf.name)	
				os.unlink(tf2.name)

			# begin accumulating new codestream
			codestreams[src_ip + "->" + dst_ip] = tcp.data
		elif tcp.data[:4]=="\x0d\x00\x05\x00": # TODO: startswith
			print " ignoring initialization pkt"
		
		else:	
			if src_ip + "->" + dst_ip in codestreams:
				print " accumulating codestream bytes"
				codestreams[src_ip + "->" + dst_ip] += tcp.data
			else:
				print " warning: never saw magic start-bytes. discarding these."
		

def main(argv):
	# TODO: drop privileges
	args=parse_args()

	pkt_num = 1

	if args.pcapfile:
		f=open(args.pcapfile, 'rb') # see dpkt issue id 27 for windows
		pcap = dpkt.pcap.Reader(f) # "ValueError: invalid tcpdump header"? don't use pcapng
                # want to track progress? total num pkts available via len(pcap.readpkts())
		for timestamp, buf in pcap:
			process_packet(pkt_num, timestamp, buf)
			pkt_num += 1
		f.close()
	elif args.network_interface:
		import pcapy
		cap=pcapy.open_live(args.network_interface,100000,1,0) # error opening adapter on windows? try pcapy.findalldevs()
		(header,payload)=cap.next()
		while header:
			process_packet(pkt_num, time.time(), payload)
			(header,payload)=cap.next() # TODO: why did i see a pcapy.PcapError (w/o details) here?
			pkt_num += 1
	# TODO: handle no args (should print usage)

if __name__ == "__main__":
    main(sys.argv)
