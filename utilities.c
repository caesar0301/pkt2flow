/* pkt2flow
 * Xiaming Chen (chen_xm@sjtu.edu.cn)
 *
 * Copyright (c) 2012
 * Copyright (c) 2014 Sven Eckelmann <sven@narfation.org>
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

#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include "pkt2flow.h"

char *new_file_name(struct af_6tuple af_6tuple, unsigned long timestamp)
{
	char *fname;
	char src_ip_str[INET6_ADDRSTRLEN];
	char dst_ip_str[INET6_ADDRSTRLEN];
	int ret;

	switch (af_6tuple.af_family) {
	case AF_INET:
		inet_ntop(AF_INET, &af_6tuple.ip1.v4, src_ip_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &af_6tuple.ip2.v4, dst_ip_str, INET_ADDRSTRLEN);
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &af_6tuple.ip1.v6, src_ip_str, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &af_6tuple.ip2.v6, dst_ip_str, INET6_ADDRSTRLEN);
		break;
	}

	switch (af_6tuple.is_vlan) {
	case 0:
		ret = asprintf(&fname, "%s_%"PRIu16"_%s_%"PRIu16"_%lu.pcap",
		       src_ip_str, af_6tuple.port1, dst_ip_str, af_6tuple.port2,
		       timestamp);
		break;
	case 1:
		ret = asprintf(&fname, "%s_%"PRIu16"_%s_%"PRIu16"_%lu_vlan.pcap",
		       src_ip_str, af_6tuple.port1, dst_ip_str, af_6tuple.port2,
		       timestamp);
		break;
	}

	if (ret < 0)
		fname = NULL;

	return fname;
}
