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
#include <strings.h>
#include "pkt2flow.h"

struct ip_pair *pairs [HASH_TBL_SIZE];

void init_hash_table(void)
{
	bzero(pairs, sizeof(struct ip_pair *) * HASH_TBL_SIZE);
}


static unsigned int hashf(char *array, unsigned int sz, unsigned int hash)
{
	unsigned int h;
	unsigned int i;

	h = hash;
	for (i = 0; i < sz; i++)
		h = (h * HASH_MULTIPLIER) + array [i];
	return (h);
}

void reset_pdf(struct pkt_dump_file *f)
{
	f->pkts = 0;
	f->start_time = 0;
	f->status = STS_UNSET;
	memset(f->file_name, '\0', FILE_NAME_LENGTH);
}

struct ip_pair *find_ip_pair(unsigned int src_ip, unsigned int dst_ip,
                             unsigned short src_tcp, unsigned short dst_tcp)
{
	struct ip_pair *p;
	struct ip_pair *newp;
	unsigned int hash = 0;
	unsigned short i;

	for (i = 0; i < 2; i++) {
		if (i == 0) {
			hash = hashf(&src_ip, 4, 0);
			hash = hashf(&dst_ip, 4, hash);
			if (src_tcp)
				hash = hashf(&src_tcp, 2, hash);
			if (dst_tcp)
				hash = hashf(&dst_tcp, 2, hash);
		} else {
			hash = hashf(&dst_ip, 4, 0);
			hash = hashf(&src_ip, 4, hash);
			if (dst_tcp)
				hash = hashf(&dst_tcp, 2, hash);
			if (src_tcp)
				hash = hashf(&src_tcp, 2, hash);
		}
		hash = hash % HASH_TBL_SIZE;
		if (pairs [hash] != NULL) {
			for (p = pairs [hash]; p != NULL; p = p->next) {
				if ((!memcmp(&src_ip, &p->ip1, 4) &&
				     !memcmp(&dst_ip, &p->ip2, 4) &&
				     !memcmp(&src_tcp, &p->port1, 2) &&
				     !memcmp(&dst_tcp, &p->port2, 2)) ||
				    (!memcmp(&dst_ip, &p->ip1, 4) &&
				     !memcmp(&src_ip, &p->ip2, 4) &&
				     !memcmp(&dst_tcp, &p->port1, 2) &&
				     !memcmp(&src_tcp, &p->port2, 2)))
					return p;
			}
		}
	}

	return NULL;
}

struct ip_pair *register_ip_pair(unsigned int src_ip, unsigned int dst_ip,
                                 unsigned short src_tcp, unsigned short dst_tcp)
{
	struct ip_pair *p;
	struct ip_pair *newp;
	unsigned int hash = 0;
	unsigned short i;

	for (i = 0; i < 2; i++) {
		if (i == 0) {
			hash = hashf(&src_ip, 4, 0);
			hash = hashf(&dst_ip, 4, hash);
			if (src_tcp)
				hash = hashf(&src_tcp, 2, hash);
			if (dst_tcp)
				hash = hashf(&dst_tcp, 2, hash);
		} else {
			hash = hashf(&dst_ip, 4, 0);
			hash = hashf(&src_ip, 4, hash);
			if (dst_tcp)
				hash = hashf(&dst_tcp, 2, hash);
			if (src_tcp)
				hash = hashf(&src_tcp, 2, hash);
		}
		hash = hash % HASH_TBL_SIZE;
	}

	newp = (struct ip_pair *)malloc(sizeof(struct ip_pair));
	if (!newp) {
		fprintf(stderr, "not enough memory to allocate another IP pair\n");
		exit(1);
	}

	memcpy(&newp->ip1, &src_ip, 4);
	memcpy(&newp->ip2, &dst_ip, 4);
	memcpy(&newp->port1, &src_tcp, 2);
	memcpy(&newp->port2, &dst_tcp, 2);
	newp->next = pairs [hash];
	pairs [hash] = newp;
	reset_pdf((struct pkt_dump_file *) & (newp->pdf));

	return newp;
}
