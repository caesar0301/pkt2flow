pkt2flow
========

by chenxm, SJTU
2012-12

Separate the packets into flows considering only 4 tuples:
source address, source port, dest address, dest port
for further analysis.

The packets are saved in the time order without any processing like TCP resembling.

The flow timeout is considered as 64 seconds suggested by CAIDA.

Usage
--------

run `scons` to compile.

usage: ./pkt2flow [-u] -o outdir pcapfile

  The seperated flows will be stored in the  "outdir", and flow names stored in "flow_names".
  
  options:
  
    -h        usage instructions 
    -u        dump UDP flows
    -o        Output directory
