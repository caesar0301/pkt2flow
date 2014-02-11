pkt2flow
========

by chenxm, Shanghai Jiao Tong Univ.
chenxm35@gmail.com

2012-12

A simple utility to classify packets into flows. It's so simple that only one task
is aimed to finish.

For Deep Packet Inspection or flow classification, it's so common to analyze the
feature of one specific flow. I have make the attempt to use made-ready tools like
`tcpflows`, `tcpslice`, `tcpsplit`, but all these tools try to either decrease the
trace volume (under requirement) or resemble the packets into flow payloads (over
requirement). I have not found a simple tool to classify the packets into flows without
further processing. This is why this program is born.

The inner function of this program behaves using the 4-tuple (src_ip, dst_ip, src_port, dst_port)
to seperate the packets into TCP or UDP flows. Each flow will be saved into a pcap 
file named with 4-tuple and the timestamp of the first packet of the flow. The packets are 
saved in the order as read from the source. Any further processing like TCP resembling is
not performed. The flow timeout is considered as 30 minutes which can be changed in pkt2flow.h.


How to compile
----------


This program is structured and compiled with a tool called SCons (http://www.scons.org/).
You can follow simple steps to make a compile:

1. Make sure you have libpcap (on Mac and Linux) in your system.

2. Install "Scons" that can be downloaded from its official website given above.

3. `cd` into the root folder of pkt2flow, and run `scons`

    $ cd ./pkt2flow
    
    $ scons


Usage
--------

Usage: ./pkt2flow [-huv] [-o outdir] pcapfile

	Options:
		-h	print this help and exit
		-u	also dump (U)DP flows
		-v	also dump the in(v)alid TCP flows without the SYN option
		-x	also dump non-UDP/non-TCP IP flows
		-o	(o)utput directory

