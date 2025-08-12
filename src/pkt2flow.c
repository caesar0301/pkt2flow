/* pkt2flow
 *
 * Copyright (c) 2012  Xiaming Chen <chen_xm@sjtu.edu.cn>
 * Copyright (C) 2014  Sven Eckelmann <sven@narfation.org>
 * Copyright (C) 2025  Xiaming Chen <chenxm35@gmail.com>
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

#include "pkt2flow.h"

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

static uint32_t dump_allowed;
static char *readfile = NULL;
// char *interface = NULL;
static char *outputdir = "pkt2flow.out";
pcap_t *inputp = NULL;
static int link_type = -1;

void open_trace_file(void) {
  char errbuf[PCAP_ERRBUF_SIZE];

  inputp = pcap_open_offline(readfile, errbuf);
  if (!inputp) {
    fprintf(stderr, "error opening tracefile %s: %s\n", readfile, errbuf);
    exit(1);
  }

  link_type = pcap_datalink(inputp);
  if (link_type == -1) {
    fprintf(stderr, "error getting link type: %s\n", pcap_geterr(inputp));
    exit(1);
  }
}

char *resemble_file_path(struct pkt_dump_file *pdf) {
  char *cwd = getcwd(NULL, 0); // backup the current working directory
  int check;
  struct stat statBuff;
  int ret;
  const char *type_folder = NULL;
  char *outputpath;
  char *dir_path = NULL;

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

  ret = asprintf(&dir_path, "%s/%s", outputdir, type_folder);
  if (ret < 0) {
    free(cwd);
    return NULL;
  }

  // Check the path folder and create the folders if they are not there
  ret = stat(dir_path, &statBuff);
  if (!(ret != -1 && S_ISDIR(statBuff.st_mode))) {
    // Create directory using mkdir -p equivalent
    char *path_copy = strdup(dir_path);
    if (!path_copy) {
      free(cwd);
      free(dir_path);
      return NULL;
    }

    char *token = strtok(path_copy, "/");
    char *current_path = NULL;

    while (token != NULL) {
      if (current_path == NULL) {
        if (dir_path[0] == '/') {
          // Absolute path
          ret = asprintf(&current_path, "/%s", token);
        } else {
          // Relative path
          ret = asprintf(&current_path, "%s", token);
        }
      } else {
        char *new_path;
        ret = asprintf(&new_path, "%s/%s", current_path, token);
        free(current_path);
        current_path = new_path;
      }

      if (ret < 0) {
        free(path_copy);
        free(current_path);
        free(cwd);
        free(dir_path);
        return NULL;
      }

      ret = stat(current_path, &statBuff);
      if (!(ret != -1 && S_ISDIR(statBuff.st_mode))) {
        check = mkdir(current_path, S_IRWXU);
        if (check != 0) {
          fprintf(stderr, "making directory error: %s\n", current_path);
          free(path_copy);
          free(current_path);
          free(cwd);
          free(dir_path);
          return NULL;
        }
      }
      token = strtok(NULL, "/");
    }
    free(path_copy);
    free(current_path);
  }

  free(cwd);

  ret = asprintf(&outputpath, "%s/%s", dir_path, pdf->file_name);
  free(dir_path);
  if (ret < 0)
    return NULL;

  return outputpath;
}

static int pcap_handle_layer4(struct af_6tuple *af_6tuple, const u_char *bytes,
                              size_t len, uint8_t proto) {
  struct tcphdr *tcphdr;
  struct udphdr *udphdr;

  switch (proto) {
  case IPPROTO_UDP:
    if (len < sizeof(*udphdr))
      return -1;

    udphdr = (struct udphdr *)bytes;
    af_6tuple->protocol = IPPROTO_UDP;
#ifdef darwin
    af_6tuple->port1 = ntohs(udphdr->uh_sport);
    af_6tuple->port2 = ntohs(udphdr->uh_dport);
#else
    af_6tuple->port1 = ntohs(udphdr->source);
    af_6tuple->port2 = ntohs(udphdr->dest);
#endif
    return 0;
  case IPPROTO_TCP:
    if (len < sizeof(*tcphdr))
      return -1;

    tcphdr = (struct tcphdr *)bytes;
    af_6tuple->protocol = IPPROTO_TCP;
#ifdef darwin
    af_6tuple->port1 = ntohs(tcphdr->th_sport);
    af_6tuple->port2 = ntohs(tcphdr->th_dport);
#else
    af_6tuple->port1 = ntohs(tcphdr->source);
    af_6tuple->port2 = ntohs(tcphdr->dest);
#endif

#ifdef darwin
    if (tcphdr->th_flags == TH_SYN)
#else
    if (tcphdr->syn)
#endif
      return 1;
    else
      return 0;
  default:
    af_6tuple->protocol = 0;
    af_6tuple->port1 = 0;
    af_6tuple->port2 = 0;
    return 0;
  }
}

static int pcap_handle_ipv4(struct af_6tuple *af_6tuple, const u_char *bytes,
                            size_t len) {
  struct ip *iphdr;

  if (len < sizeof(*iphdr))
    return -1;

  iphdr = (struct ip *)bytes;
  if (len > ntohs(iphdr->ip_len))
    len = ntohs(iphdr->ip_len);

  if (len < 4 * iphdr->ip_hl)
    return -1;

  len -= 4 * iphdr->ip_hl;
  bytes += 4 * iphdr->ip_hl;

  af_6tuple->af_family = AF_INET;
  af_6tuple->ip1.v4 = iphdr->ip_src;
  af_6tuple->ip2.v4 = iphdr->ip_dst;

  return pcap_handle_layer4(af_6tuple, bytes, len, iphdr->ip_p);
}

static int pcap_handle_ipv6(struct af_6tuple *af_6tuple, const u_char *bytes,
                            size_t len) {
  struct ip6_hdr *iphdr;
  struct ip6_opt *opthdr;
  int curheader = 255;
  uint8_t nexthdr;

  while (1) {
    switch (curheader) {
    case 255:
      if (len < sizeof(*iphdr))
        return -1;
      iphdr = (struct ip6_hdr *)bytes;
      bytes += sizeof(*iphdr);
      len -= sizeof(*iphdr);
      nexthdr = iphdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;

      af_6tuple->af_family = AF_INET6;
      af_6tuple->ip1.v6 = iphdr->ip6_src;
      af_6tuple->ip2.v6 = iphdr->ip6_dst;
      break;
    case IPPROTO_HOPOPTS:
    case IPPROTO_ROUTING:
    case IPPROTO_DSTOPTS:
      if (len < sizeof(*opthdr))
        return -1;
      nexthdr = bytes[0];

      opthdr = (struct ip6_opt *)bytes;
      if (len < ((1u + opthdr->ip6o_len) * 8u))
        return -1;
      bytes += (1u + opthdr->ip6o_len) * 8u;
      len -= (1u + opthdr->ip6o_len) * 8u;
      break;
    case IPPROTO_FRAGMENT:
      if (len < 1)
        return -1;
      nexthdr = bytes[0];
      if (len < 8)
        return -1;
      bytes += 8;
      len -= 8;
      break;
    case IPPROTO_NONE:
      return -1;
    default:
      return pcap_handle_layer4(af_6tuple, bytes, len, nexthdr);
    };
    curheader = nexthdr;
  }
}

static int pcap_handle_ip(struct af_6tuple *af_6tuple, const u_char *bytes,
                          size_t len) {
  if (len < 1)
    return -1;

  /* IP header */
  if ((bytes[0] >> 4) == 4)
    return pcap_handle_ipv4(af_6tuple, bytes, len);

  if ((bytes[0] >> 4) == 6)
    return pcap_handle_ipv6(af_6tuple, bytes, len);

  return -1;
}

int pcap_handle_ethernet(struct af_6tuple *af_6tuple,
                         const struct pcap_pkthdr *h, const u_char *bytes) {
  size_t len = h->caplen;
  struct ether_header *ethhdr;

  /* Ethernet header */
  if (len < sizeof(*ethhdr))
    return -1;

  ethhdr = (struct ether_header *)bytes;
  len -= sizeof(*ethhdr);
  bytes += sizeof(*ethhdr);

  struct vlan_header *vlanhdr;
  uint16_t etype = ntohs(ethhdr->ether_type);

  /* VLAN header, IEEE 802.1Q */
  if (etype == ETHERTYPE_VLAN) {
    vlanhdr = (struct vlan_header *)bytes;
    etype = ntohs(vlanhdr->tpid);
    bytes += sizeof(*vlanhdr);
    len -= sizeof(*vlanhdr);
    af_6tuple->is_vlan = 1;
  } else {
    af_6tuple->is_vlan = 0;
  }

  if (etype != ETHERTYPE_IP && etype != ETHERTYPE_IPV6)
    return -1;

  return pcap_handle_ip(af_6tuple, bytes, len);
}

int pcap_handle_raw_ip(struct af_6tuple *af_6tuple, const struct pcap_pkthdr *h,
                       const u_char *bytes) {
  size_t len = h->caplen;

  /* For raw IP packets, the packet starts directly with IP header */
  af_6tuple->is_vlan = 0;

  return pcap_handle_ip(af_6tuple, bytes, len);
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *hdr,
                           const u_char *pkt) {
  (void)user; // Suppress unused parameter warning
  int syn_detected;
  struct ip_pair *pair = NULL;
  char *fname = NULL;
  struct af_6tuple af_6tuple;

  /* Handle different link types */
  switch (link_type) {
  case DLT_EN10MB:      /* Ethernet */
  case DLT_IEEE802:     /* Token Ring */
  case DLT_ARCNET:      /* ARCNET */
  case DLT_SLIP:        /* SLIP */
  case DLT_PPP:         /* PPP */
  case DLT_FDDI:        /* FDDI */
  case DLT_ATM_RFC1483: /* ATM RFC1483 */
  case DLT_RAW:         /* Raw IP */
    if (link_type == DLT_RAW) {
      syn_detected = pcap_handle_raw_ip(&af_6tuple, hdr, pkt);
    } else {
      syn_detected = pcap_handle_ethernet(&af_6tuple, hdr, pkt);
    }
    break;
  default:
    fprintf(stderr, "Unsupported link type: %d\n", link_type);
    return;
  }

  if (syn_detected < 0)
    return;

  switch (af_6tuple.protocol) {
  case IPPROTO_TCP:
    /* always accept tcp */
    break;
  case IPPROTO_UDP:
    if (!isset_bits(dump_allowed, DUMP_UDP_ALLOWED))
      // Omit the UDP packets
      return;
    break;
  default:
    if (!isset_bits(dump_allowed, DUMP_OTHER_ALLOWED))
      // Omit the other packets
      return;
    break;
  }

  // Search for the ip_pair of specific six-tuple
  pair = find_ip_pair(af_6tuple);
  if (pair == NULL) {
    if ((af_6tuple.protocol == IPPROTO_TCP) && !syn_detected &&
        !isset_bits(dump_allowed, DUMP_TCP_NOSYN_ALLOWED)) {
      // No SYN detected and don't create a new flow
      return;
    }
    pair = register_ip_pair(af_6tuple);
    switch (af_6tuple.protocol) {
    case IPPROTO_TCP:
      if (syn_detected)
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
    fname = new_file_name(af_6tuple, hdr->ts.tv_sec);
    pair->pdf.file_name = fname;
    pair->pdf.start_time = hdr->ts.tv_sec;
  } else {
    if (hdr->ts.tv_sec - pair->pdf.start_time >= FLOW_TIMEOUT) {
      // Rest the pair to start a new flow with the same 6-tuple, but with
      // the different name and timestamp
      reset_pdf(&(pair->pdf));
      fname = new_file_name(af_6tuple, hdr->ts.tv_sec);
      pair->pdf.file_name = fname;
      pair->pdf.start_time = hdr->ts.tv_sec;

      switch (af_6tuple.protocol) {
      case IPPROTO_TCP:
        if (syn_detected)
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
  }

  // Dump the packet to file
  fname = resemble_file_path(&(pair->pdf));
  if (!fname) {
    fprintf(stderr, "Failed to create file path\n");
    return;
  }

  if (pair->pdf.pkts == 0) {
    // First packet in this flow - create a new file with pcap header
    FILE *f = fopen(fname, "wb");
    if (!f) {
      fprintf(stderr, "Failed to open output file '%s'\n", fname);
      free(fname);
      return;
    }
    pair->pdf.dumper = pcap_dump_fopen(inputp, f);
    if (!pair->pdf.dumper) {
      fprintf(stderr, "Failed to create pcap dumper\n");
      fclose(f);
      free(fname);
      return;
    }
  }

  // Dump the packet using the existing dumper
  pcap_dump((u_char *)pair->pdf.dumper, hdr, (unsigned char *)pkt);
  pcap_dump_flush(pair->pdf.dumper);

  free(fname);
  pair->pdf.pkts++;
}

void set_dump_allowed(uint32_t flags) { dump_allowed = flags; }

void set_readfile(const char *filename) { readfile = (char *)filename; }

void set_outputdir(const char *dir) { outputdir = (char *)dir; }

void process_trace(void) { pcap_loop(inputp, -1, packet_handler, NULL); }

void close_trace_files(void) { pcap_close(inputp); }
