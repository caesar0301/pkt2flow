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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
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

static uint32_t dump_allowed;
static char *readfile = NULL;
//char *interface = NULL;
static char *outputdir = "pkt2flow.out";
static pcap_t *inputp = NULL;
struct ip_pair *pairs[HASH_TBL_SIZE];

static void usage(char *progname)
{
	fprintf(stderr, "Name: %s\n", __GLOBAL_NAME__);
	fprintf(stderr, "Version: %s\n", __SOURCE_VERSION__);
	fprintf(stderr, "Author: %s\n", __AUTHOR__);
	fprintf(stderr, "Program to seperate the packets into flows (UDP or TCP).\n\n");
	fprintf(stderr, "Usage: %s [-huvx] [-o outdir] pcapfile\n\n", progname);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "	-h	print this help and exit\n");
	fprintf(stderr, "	-u	also dump (U)DP flows\n");
	fprintf(stderr, "	-v	also dump the in(v)alid TCP flows without the SYN option\n");
	fprintf(stderr, "	-x	also dump non-UDP/non-TCP IP flows\n");
	fprintf(stderr, "	-o	(o)utput directory\n");
}


static void parseargs(int argc, char *argv[])
{
	int opt;
	const char *optstr = "uvxo:h";
	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv [0]);
			exit(-1);
		case 'o':
			outputdir = optarg;
			break;
		case 'u':
			dump_allowed |= DUMP_UDP_ALLOWED;
			break;
		case 'v':
			dump_allowed |= DUMP_TCP_NOSYN_ALLOWED;
			break;
		case 'x':
			dump_allowed |= DUMP_OTHER_ALLOWED;
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
	int check;
	struct stat statBuff;
	int ret;
	const char *type_folder;
	char *outputpath;

	switch (pdf->status) {
	case STS_TCP_SYN:
		type_folder = "tcp_syn";
		break;
	case STS_TCP_NOSYN:
		type_folder = "tcp_nosyn";
		break;
	case STS_UDP:
		type_folder = "udp";
		break;
	case STS_UNSET:
		type_folder = "others";
		break;
	}

	ret = asprintf(&outputpath, "%s/%s", outputdir, type_folder);
	if (ret < 0)
		return NULL;

	// Check the path folder and create the folders if they are not there
	ret = stat(outputpath, &statBuff);
	if (!(ret != -1 && S_ISDIR(statBuff.st_mode))) {
		folder = strtok(outputpath, "/");
		while (folder != NULL) {
			ret = stat(folder, &statBuff);
			if (!(ret != -1 && S_ISDIR(statBuff.st_mode))) {
				check = mkdir(folder, S_IRWXU);
				if (check != 0) {
					fprintf(stderr, "making directory error: %s\n",
						folder);
					exit(-1);
				}
			}
			chdir(folder);
			folder = strtok(NULL, "/");
		}
	}
	chdir(cwd);
	free(cwd);
	free(outputpath);

	ret = asprintf(&outputpath, "%s/%s/%s", outputdir, type_folder,
		       pdf->file_name);
	if (ret < 0)
		return NULL;

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
	pcap_dumper_t *dumper = NULL;
	u_char *pkt = NULL;
	char *fname = NULL;
	unsigned short offset;
	struct af_6tuple af_6tuple;

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
		af_6tuple.af_family = AF_INET;
		af_6tuple.ip1.v4 = iph->ip_src;
		af_6tuple.ip2.v4 = iph->ip_dst;

		offset = EH_SIZE + (iph->ip_hl * 4);
		switch (iph->ip_p) {
		case IPPROTO_TCP:
			/* always accept tcp */
			break;
		case IPPROTO_UDP:
			if (!isset_bits(dump_allowed, DUMP_UDP_ALLOWED))
				// Omit the UDP packets
				continue;
			break;
		default:
			if (!isset_bits(dump_allowed, DUMP_OTHER_ALLOWED))
				// Omit the other packets
				continue;
			break;
		}

		// Get the src and dst ports of TCP or UDP
		switch (iph->ip_p) {
		case IPPROTO_TCP:
			if (hdr.caplen < offset + sizeof(struct tcphdr))
				continue;
			tcph = (struct tcphdr *)(pkt + offset);
			af_6tuple.protocol = IPPROTO_TCP;
			af_6tuple.port1 = ntohs(tcph->source);
			af_6tuple.port2 = ntohs(tcph->dest);
			break;
		case IPPROTO_UDP:
			if (hdr.caplen < offset + sizeof(struct udphdr))
				continue;
			udph = (struct udphdr *)(pkt + offset);
			af_6tuple.protocol = IPPROTO_UDP;
			af_6tuple.port1 = ntohs(udph->source);
			af_6tuple.port2 = ntohs(udph->dest);
			break;
		default:
			af_6tuple.protocol = 0;
			af_6tuple.port1 = 0;
			af_6tuple.port2 = 0;
			break;
		}

		// Search for the ip_pair of specific six-tuple
		pair = find_ip_pair(af_6tuple);
		if (pair == NULL) {
			if ((af_6tuple.protocol == IPPROTO_TCP) && !tcph->syn &&
			    !isset_bits(dump_allowed, DUMP_TCP_NOSYN_ALLOWED)) {
				// No SYN detected and don't create a new flow
				continue;
			}
			pair = register_ip_pair(af_6tuple);
			switch (af_6tuple.protocol) {
			case IPPROTO_TCP:
				if (tcph->syn)
					pair->pdf.status = STS_TCP_SYN;
				else
					pair->pdf.status = STS_TCP_NOSYN;
				break;
			case IPPROTO_UDP:
				pair->pdf.status = STS_UDP;
				break;
			default:
				pair->pdf.status = STS_UNSET;
				break;
			}
		}

		// Fill the ip_pair with information of the current flow
		if (pair->pdf.pkts == 0) {
			// A new flow item reated with empty dump file object
			fname = new_file_name(af_6tuple, hdr.ts.tv_sec);
			pair->pdf.file_name = fname;
			pair->pdf.start_time = hdr.ts.tv_sec;
		} else {
			if (hdr.ts.tv_sec - pair->pdf.start_time >= FLOW_TIMEOUT) {
				// Rest the pair to start a new flow with the same 6-tuple, but with
				// the different name and timestamp
				reset_pdf(&(pair->pdf));
				fname = new_file_name(af_6tuple, hdr.ts.tv_sec);
				pair->pdf.file_name = fname;
				pair->pdf.start_time = hdr.ts.tv_sec;
			}
		}

		// Dump the packet to file and close the file
		fname = resemble_file_path(&(pair->pdf));
		FILE *f = fopen(fname, "ab");
		free(fname);
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
	free_hash_table();
	exit(0);
}
