
/* tcpsplit
 * Mark Allman (mallman@icir.org)
 * 
 * Copyright (c) 2004 International Computer Science Institute
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include "pkt2flow.h"

char *readfile = NULL;
char *outputdir = NULL;
char dumpudp = 0;
pcap_t *inputp = NULL;
struct ip_pair *pairs [HASH_TBL_SIZE];
char *flownames = "flow_names";

void usage (char *progname)
{
    fprintf (stderr,"usage: %s [-u] -o outdir pcapfile\n", progname);
    fprintf (stderr,"  The seperated flows will be stored in the  \"outdir\",\
and flow names stored in \"flow_names\".\n");
    fprintf (stderr,"  options:\n");
    fprintf (stderr,"    -h        usage instructions\n");
	fprintf (stderr,"    -u        dump UDP flows\n");
    fprintf (stderr,"    -o        Output directory\n");
    exit (1);
}


void parseargs (int argc,char *argv[])
{
	int opt;
	const char *optstr = "uo:h";
	while((opt = getopt(argc, argv, optstr)) != -1){
		switch(opt){
			case 'h':
				usage(argv [0]);
				exit(-1);
			case 'o':
				outputdir = optarg;
				break;
			case 'u':
				dumpudp = 1;
				break;
			default:
				usage(argv [0]);
				exit(-1);
		}
	}
	
	if (optind < argc)
		readfile = argv[optind];
	if((readfile == NULL) || (outputdir == NULL))
		usage(argv[0]);
	if(access(outputdir, F_OK) != 0){
		fprintf(stderr, "output folder dost not exist.\n");
		exit(-1);	
	}
}

void record_flow_name(char *fname){
	FILE *f = fopen(flownames, "a+");
	fputs(fname, f);
	fputc('\n', f);
	fclose(f);
}

void open_trace_file ()
{
    char errbuf [PCAP_ERRBUF_SIZE];
	
    if ((inputp = pcap_open_offline (readfile, errbuf)) == NULL){
		fprintf (stderr,"error opening tracefile %s: %s\n", readfile, errbuf);
		exit (1);
	}
}


void process_trace ()
{
    struct pcap_pkthdr hdr;
	struct ether_header *ethh = NULL;
    struct ip *iph = NULL;
    struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
    u_char *pkt = NULL;
    struct pkt_dump_file *pdf = NULL;
	struct pcap_dumper_t *dumper = NULL;
    unsigned short offset;
	unsigned long src_ip, dst_ip;
    unsigned short src_port, dst_port;
	char *fname = NULL;
	char *filepath = NULL;
	unsigned short fplen = strlen(outputdir)+FILE_NAME_LENGTH+2;
	
	filepath = malloc(fplen);
    while ((pkt = (u_char *)pcap_next (inputp, &hdr)) != NULL){
		ethh = (struct ether_header *)pkt;
		if (hdr.caplen < (EH_SIZE + sizeof (struct ip)) || ntohs(ethh->ether_type) != EH_IP){
		    // Omit the non-IP packets
		    continue;
		}
		if ((iph = (struct ip *)(pkt + EH_SIZE)) == NULL){
		    continue;
		}
		src_ip = ntohl(iph->ip_src.s_addr);
		dst_ip = ntohl(iph->ip_dst.s_addr);
		
		offset = EH_SIZE + (iph->ip_hl * 4);
		if (iph->ip_p != IPPROTO_TCP ){
			if(dumpudp == 0)
			// Omit the non-TCP packets
			continue;
			else
				if(iph->ip_p != IPPROTO_UDP)
				// Omit the non-TCP or non-UDP packets
				continue;
		}
		if (iph->ip_p == IPPROTO_TCP){
			if (hdr.caplen < offset + sizeof(struct tcphdr))
				continue;
			tcph = (struct tcphdr *)(pkt + offset);
		    src_port = ntohs(tcph->th_sport);
		    dst_port = ntohs(tcph->th_dport);
		}
		if (iph->ip_p == IPPROTO_UDP){
			if (hdr.caplen < offset + sizeof(struct udphdr))
				continue;
			udph = (struct udph *)(pkt + offset);
		    src_port = ntohs(udph->uh_sport);
		    dst_port = ntohs(udph->uh_dport);
		}
		// Search for the packet dump file obj
		pdf = get_pkt_dump_file (iph->ip_src.s_addr,iph->ip_dst.s_addr,src_port, dst_port);
		if(pdf->file_name[0] == '\n'){
			fname = new_file_name(src_ip, dst_ip, src_port, dst_port, hdr.ts.tv_sec);
			record_flow_name(fname);
			memset(pdf->file_name, '\0', FILE_NAME_LENGTH);
			memcpy(pdf->file_name, fname, strlen(fname));
			pdf->start_time = hdr.ts.tv_sec;
			pdf->pkts = 0;
			free(fname);
		}else{
			if(hdr.ts.tv_sec - pdf->start_time >= FLOW_TIMEOUT){
				fname = new_file_name(src_ip, dst_ip, src_port, dst_port, hdr.ts.tv_sec);
				record_flow_name(fname);
				memset(pdf->file_name, '\0', FILE_NAME_LENGTH);
				memcpy(pdf->file_name, fname, strlen(fname));
				pdf->start_time = hdr.ts.tv_sec;
				pdf->pkts = 0;
				free(fname);
			}
		}
		// Dump the packet to file
		memset(filepath, '\0', fplen);
		strcpy(filepath, outputdir);
		strcat(filepath, "/");
		strcat(filepath, pdf->file_name);
		FILE *f = fopen(filepath, "ab");
		if(pdf->pkts == 0){
			dumper = pcap_dump_fopen(inputp, f);
		}else{
			dumper = (pcap_dumper_t *)f;
		}
		pcap_dump ((u_char *)dumper, &hdr, (unsigned char *)pkt);
		pcap_dump_close(dumper);
		pdf->pkts++;
    }
	free(filepath);
}


void close_trace_files ()
{
    pcap_close (inputp);
}


int main (argc,argv)
int argc;
char *argv [];
{
    parseargs (argc,argv);
    open_trace_file ();
    init_hash_table ();
    process_trace ();
    close_trace_files ();
    exit (0);
}
