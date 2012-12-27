
/* pkt2flow
 * Xiaming Chen (chen_xm@sjtu.edu.cn)
 * 
 * Copyright (c) 2012
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * The names and trademarks of copyright holders may not be used in
 * advertising or publicity pertaining to the software without specific
 * prior permission. Title to copyright in this software and any
 * associated documentation will at all times remain with the copyright
 * holders.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#include <pcap.h>


#define FLOW_TIMEOUT		   1800	// seconds
#define HASH_MULTIPLIER        37
#define HASH_TBL_SIZE          48611
#define EH_SIZE                14
#define EH_IP				   0x0800
#define FILE_NAME_LENGTH       128


struct pkt_dump_file
{
	char file_name[FILE_NAME_LENGTH];
    unsigned long pkts;
	unsigned long start_time;
};

struct ip_pair
{
    unsigned int ip1, ip2;
    unsigned short port1, port2;
	struct pkt_dump_file pdf;
    struct ip_pair *next;
};

/* utilities.c */

char *new_file_name(unsigned int src_ip, unsigned int dst_ip, unsigned short src_tcp, unsigned short dst_tcp, unsigned long timestamp);

/* ipa_db.c */

void init_hash_table ();
void reset_pkt_dump_file (struct pkt_dump_file *f);
struct pkt_dump_file *
	get_pkt_dump_file (unsigned int src_ip, unsigned int dst_ip, unsigned short src_tcp, unsigned short dst_tcp);

/* pkt2flow.c */

extern struct ip_pair *pairs[];