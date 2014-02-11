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
#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include "pkt2flow.h"

static char tcpsyn = 1;
static char dumpudp = 0;
static char *readfile = NULL;
//char *interface = NULL;
static char *outputdir = "pkt2flow.out";
static char outputpath[PATH_NAME_LENGTH];
static pcap_t *inputp = NULL;
struct ip_pair *pairs[HASH_TBL_SIZE];

static void usage(char *progname)
{
	fprintf(stderr, "Name: %s\n", __GLOBAL_NAME__);
	fprintf(stderr, "Version: %s\n", __VERSION__);
	fprintf(stderr, "Author: %s\n", __AUTHOR__);
	fprintf(stderr, "Program to seperate the packets into flows (UDP or TCP).\n\n");
	fprintf(stderr, "Usage: %s [-huv] [-o outdir] pcapfile\n\n", progname);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "	-h	print this help and exit\n");
	fprintf(stderr, "	-u	also dump (U)DP flows\n");
	fprintf(stderr, "	-v	also dump the in(v)alid TCP flows without the SYN option\n");
	fprintf(stderr, "	-o	(o)utput directory\n");
}


static void parseargs(int argc, char *argv[])
{
	int opt;
	const char *optstr = "uvo:h";
	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv [0]);
			exit(-1);
		case 'o':
			outputdir = optarg;
			break;
		case 'u':
			dumpudp = 1;
			break;
		case 'v':
			tcpsyn = 0;
			break;
		default:
			usage(argv [0]);
			exit(-1);
		}
	}

	if (optind < argc)
		readfile = argv[optind];
	if (readfile == NULL) {
		fprintf(stderr, "pcap file not given\n");
		usage(argv[0]);
		exit(1);
	}
}

static void open_trace_file(void)
{
	char errbuf [PCAP_ERRBUF_SIZE];

	inputp = pcap_open_offline(readfile, errbuf);
	if (!inputp) {
		fprintf(stderr, "error opening tracefile %s: %s\n", readfile,
			errbuf);
		exit(1);
	}
}

static char *resemble_file_path(struct pkt_dump_file *pdf)
{
	char *cwd = getcwd(NULL, 0);    // backup the current working directory
	char *folder = NULL;
	char *dupPath = NULL;
	int check;
	struct stat statBuff;
	int ret;

	strcpy(outputpath, outputdir);
	strcat(outputpath, "/");
	if (pdf->status == STS_TCP_SYN)
		strcat(outputpath, "tcp_syn/");
	else if (pdf->status == STS_TCP_NOSYN)
		strcat(outputpath, "tcp_nosyn/");
	else if (pdf->status == STS_UDP)
		strcat(outputpath, "udp/");
	else
		strcat(outputpath, "others/");

	// Check the path folder and create the folders if they are not there
	dupPath = strdup(outputpath);
	ret = stat(dupPath, &statBuff);
	if (!(ret != -1 && S_ISDIR(statBuff.st_mode))) {
		folder = strtok(dupPath, "/");
		while (folder != NULL) {
			ret = stat(folder, &statBuff);
			if (!(ret != -1 && S_ISDIR(statBuff.st_mode))) {
				check = mkdir(folder, S_IRWXU);
				if (check != 0) {
					fprintf(stderr, "making directory error: %s\n",
						dupPath);
					exit(-1);
				}
			}
			chdir(folder);
			folder = strtok(NULL, "/");
		}
	}
	chdir(cwd);
	free(cwd);
	free(dupPath);
	strcat(outputpath, pdf->file_name);
	return outputpath;
}

static void process_trace(void)
{
	struct pcap_pkthdr hdr;
	struct ether_header *ethh = NULL;
	struct ip *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct udphdr *udph = NULL;
	struct ip_pair *pair =  NULL;
	struct pcap_dumper_t *dumper = NULL;
	u_char *pkt = NULL;
	char *fname = NULL;
	unsigned short offset;
	unsigned long src_ip, dst_ip;
	unsigned short src_port, dst_port;

	while ((pkt = (u_char *)pcap_next(inputp, &hdr)) != NULL) {
		// Get IP layer information
		ethh = (struct ether_header *)pkt;
		if (hdr.caplen < (EH_SIZE + sizeof(struct ip)) ||
		    ntohs(ethh->ether_type) != EH_IP) {
			// Omit the non-IP packets
			continue;
		}
		if ((iph = (struct ip *)(pkt + EH_SIZE)) == NULL) {
			continue;
		}
		src_ip = ntohl(iph->ip_src.s_addr);
		dst_ip = ntohl(iph->ip_dst.s_addr);

		offset = EH_SIZE + (iph->ip_hl * 4);
		if (iph->ip_p != IPPROTO_TCP) {
			// Check the flag to dump UDP or not
			if (dumpudp == 0)
				// Omit the non-TCP packets
				continue;
			else if (iph->ip_p != IPPROTO_UDP)
				// Omit the non-TCP or non-UDP packets
				continue;
		}

		// Get the src and dst ports of TCP or UDP
		if (iph->ip_p == IPPROTO_TCP) {
			if (hdr.caplen < offset + sizeof(struct tcphdr))
				continue;
			tcph = (struct tcphdr *)(pkt + offset);
			src_port = ntohs(tcph->th_sport);
			dst_port = ntohs(tcph->th_dport);
		}
		if (iph->ip_p == IPPROTO_UDP) {
			if (hdr.caplen < offset + sizeof(struct udphdr))
				continue;
			udph = (struct udph *)(pkt + offset);
			src_port = ntohs(udph->uh_sport);
			dst_port = ntohs(udph->uh_dport);
		}

		// Search for the ip_pair of specific four-tuple
		pair = find_ip_pair(iph->ip_src.s_addr, iph->ip_dst.s_addr,
				    src_port, dst_port);
		if (pair == NULL) {
			if ((iph->ip_p == IPPROTO_TCP) && (tcpsyn == 1) &&
			    ((tcph->th_flags & TH_SYN) != TH_SYN)) {
				// No SYN detected and don't create a new flow
				continue;
			}
			pair = register_ip_pair(iph->ip_src.s_addr,
						iph->ip_dst.s_addr, src_port,
						dst_port);
			if (iph->ip_p == IPPROTO_UDP)
				pair->pdf.status = STS_UDP;
			else {
				if ((tcph->th_flags & TH_SYN) == TH_SYN)
					pair->pdf.status = STS_TCP_SYN;
				else
					pair->pdf.status = STS_TCP_NOSYN;
			}
		}

		// Fill the ip_pair with information of the current flow
		if (pair->pdf.pkts == 0) {
			// A new flow item reated with empty dump file object
			fname = new_file_name(src_ip, dst_ip, src_port,
					      dst_port, hdr.ts.tv_sec);
			memcpy(pair->pdf.file_name, fname, strlen(fname));
			pair->pdf.start_time = hdr.ts.tv_sec;
			free(fname);
		} else {
			if (hdr.ts.tv_sec - pair->pdf.start_time >= FLOW_TIMEOUT) {
				// Rest the pair to start a new flow with the same 4-tuple, but with
				// the different name and timestamp
				reset_pdf(&(pair->pdf));
				fname = new_file_name(src_ip, dst_ip, src_port,
						      dst_port, hdr.ts.tv_sec);
				memcpy(pair->pdf.file_name, fname, strlen(fname));
				pair->pdf.start_time = hdr.ts.tv_sec;
				free(fname);
			}
		}

		// Dump the packet to file and close the file
		FILE *f = fopen(resemble_file_path(&(pair->pdf)), "ab");
		if (pair->pdf.pkts == 0) {
			// Call the pcap_dump_fopen to write the pcap file header first
			// to the new file
			dumper = pcap_dump_fopen(inputp, f);
		} else {
			// Write the packet only
			dumper = (pcap_dumper_t *)f;
		}
		// Dump the packet now
		pcap_dump((u_char *)dumper, &hdr, (unsigned char *)pkt);
		pcap_dump_close(dumper);
		pair->pdf.pkts++;
	}
}


static void close_trace_files(void)
{
	pcap_close(inputp);
}


int main(int argc, char *argv[])
{
	parseargs(argc, argv);
	open_trace_file();
	init_hash_table();
	process_trace();
	close_trace_files();
	exit(0);
}
