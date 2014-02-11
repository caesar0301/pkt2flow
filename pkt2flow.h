
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

#define __VERSION__				"1.2"
#define __AUTHOR__				"X. Chen (chenxm35@gmail.com)"
#define __GLOBAL_NAME__			"pkt2flow"
#define EH_SIZE					14
#define EH_IP					0x0800
#define FLOW_TIMEOUT			1800	// seconds
#define HASH_MULTIPLIER			37
#define HASH_TBL_SIZE			48611
#define FILE_NAME_LENGTH		128
#define PATH_NAME_LENGTH		1024

struct pkt_dump_file
{
	char file_name[FILE_NAME_LENGTH];
    unsigned long pkts;
#define STS_UNSET			0x0000
#define STS_TCP_SYN			0x0001
#define STS_TCP_NOSYN		0x0010
#define STS_UDP				0x1000
	unsigned int status;
	unsigned long start_time;
};

struct ip_pair
{
    unsigned int ip1, ip2;
    unsigned short port1, port2;
	struct pkt_dump_file pdf;
    struct ip_pair *next;
};

/* pkt2flow.c */
extern struct ip_pair *pairs[];

/* utilities.c */

/*
* Generate a new file name for flow with 4-tuple and timestamp
*/
char *new_file_name(unsigned int src_ip, unsigned int dst_ip, unsigned short src_tcp, unsigned short dst_tcp, unsigned long timestamp);

/* flow_db.c */

/*
* Initialize the flow hash table to store registered flow items
*/
void init_hash_table ();

/*
* Search for the flow in the flow hash table with specific 4-tuple;
* If the flow item exists in the hash table, the pointer to the ip_pair will be returned
* Otherwise, NULL returned;
*/
struct ip_pair *
find_ip_pair (unsigned int src_ip, unsigned int dst_ip, unsigned short src_tcp, unsigned short dst_tcp);

/*
* To register a new flow item in the flow hash table. This is uaually called after finding the
* flow item with NULL returned. 
* The pointer to the new registerd ip_pair will be returned; and the pdf will be reset as empty.
*/
struct ip_pair *
register_ip_pair (unsigned int src_ip, unsigned int dst_ip, unsigned short src_tcp, unsigned short dst_tcp);

/*
* Reset the packet dump file (pdf) for: 1) a new ip_pair created; 
* 2) a timeout flow with new status.
* The pdf will be reset with: zero packets, zero timestamp, 
* and file name bytes all set to be '\0'
*/
void reset_pdf (struct pkt_dump_file *f);

