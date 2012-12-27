pkt2flow
========

by chenxm, SJTU
2012-12

To seperate the packets into flows (UDP or TCP) by 4-tuple of (src_ip, dst_ip, src_port, dst_port).
Each flow will be saved into a pcap file named with 4_tuple and the timestamp of
the first packet of the flow for further analysis, e.g., using tcpflow, tcptrace, captcp.py etc.

The packets are saved in the time order without any processing like TCP resembling.

The flow timeout is considered as 30 minutes which can be changed in pkt2flow.h.

Usage
--------

run `scons` to compile.

usage: ./pkt2flow [-u] -o outdir pcapfile

  options:
  
    -h        usage instructions
    -v        dump the validated TCP flows only with the first SYN detected
    -u        dump UDP flows
    -o        Output directory
