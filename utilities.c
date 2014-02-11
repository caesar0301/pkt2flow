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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include "pkt2flow.h"

char *new_file_name(struct in_addr src_ip, struct in_addr dst_ip,
                    uint16_t src_tcp, uint16_t dst_tcp,
                    unsigned long timestamp)
{
	char *fname;
	char src_ip_str[INET_ADDRSTRLEN];
	char dst_ip_str[INET_ADDRSTRLEN];
	int ret;

	inet_ntop(AF_INET, &src_ip, src_ip_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &dst_ip, dst_ip_str, INET_ADDRSTRLEN);

	ret = asprintf(&fname, "%s_%"PRIu16"_%s_%"PRIu16"_%lu.pcap",
		       src_ip_str, src_tcp, dst_ip_str, dst_tcp, timestamp);
	if (ret < 0)
		fname = NULL;

	return fname;
}
