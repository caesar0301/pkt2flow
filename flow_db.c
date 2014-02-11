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

#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "pkt2flow.h"

struct ip_pair *pairs [HASH_TBL_SIZE];

void init_hash_table(void)
{
	memset(pairs, 0, sizeof(struct ip_pair *) * HASH_TBL_SIZE);
}

void free_hash_table(void)
{
	size_t b;
	struct ip_pair *curp;

	for (b = 0; b < HASH_TBL_SIZE; b++) {
		while (pairs[b]) {
			curp = pairs[b];
			pairs[b] = pairs[b]->next;
			reset_pdf(&curp->pdf);
			free(curp);
		}
	}

	init_hash_table();
}

static unsigned int hashf(const void *key, size_t sz, unsigned int hash)
{
	unsigned int h;
	unsigned int i;
	const unsigned char *array = key;

	h = hash;
	for (i = 0; i < sz; i++)
		h = (h * HASH_MULTIPLIER) + array[i];
	return (h);
}

void reset_pdf(struct pkt_dump_file *f)
{
	f->pkts = 0;
	f->start_time = 0;
	f->status = STS_UNSET;
	free(f->file_name);
	f->file_name = NULL;
}

static unsigned int hash_5tuple(struct af_6tuple af_6tuple)
{
	unsigned int hash1 = 0;
	unsigned int hash2 = 0;
	int i;

	for (i = 0; i < 2; i++) {
		if (i == 0) {
			switch (af_6tuple.af_family) {
			case AF_INET:
				hash1 = hashf(&af_6tuple.ip1.v4, 4, hash1);
				hash1 = hashf(&af_6tuple.ip2.v4, 4, hash1);
				break;
			case AF_INET6:
				hash1 = hashf(&af_6tuple.ip1.v6, 16, hash1);
				hash1 = hashf(&af_6tuple.ip2.v6, 16, hash1);
				break;
			}
			if (af_6tuple.port1)
				hash1 = hashf(&af_6tuple.port1, 2, hash1);
			if (af_6tuple.port2)
				hash1 = hashf(&af_6tuple.port2, 2, hash1);
		} else {
			switch (af_6tuple.af_family) {
			case AF_INET:
				hash2 = hashf(&af_6tuple.ip2.v4, 4, hash2);
				hash2 = hashf(&af_6tuple.ip1.v4, 4, hash2);
				break;
			case AF_INET6:
				hash2 = hashf(&af_6tuple.ip2.v6, 16, hash2);
				hash2 = hashf(&af_6tuple.ip1.v6, 16, hash2);
				break;
			}
			if (af_6tuple.port2)
				hash2 = hashf(&af_6tuple.port2, 2, hash2);
			if (af_6tuple.port1)
				hash2 = hashf(&af_6tuple.port1, 2, hash2);
		}
	}

	return (hash1 + hash2) % HASH_TBL_SIZE;
}

static int compare_5tuple(struct af_6tuple af1, struct af_6tuple af2)
{
	if (af1.af_family != af2.af_family)
		return 0;

	if (af1.protocol != af2.protocol)
		return 0;

	switch (af1.af_family) {
	case AF_INET:
		if (memcmp(&af1.ip1.v4, &af2.ip1.v4, sizeof(af1.ip1.v4)) == 0 &&
		    memcmp(&af1.ip2.v4, &af2.ip2.v4, sizeof(af1.ip2.v4)) == 0 &&
		    af1.port1 == af2.port1 && af1.port2 == af2.port2)
			return 1;
		if (memcmp(&af1.ip1.v4, &af2.ip2.v4, sizeof(af1.ip1.v4)) == 0 &&
		    memcmp(&af1.ip2.v4, &af2.ip1.v4, sizeof(af1.ip2.v4)) == 0 &&
		    af1.port1 == af2.port2 && af1.port2 == af2.port1)
			return 1;
		break;
	case AF_INET6:
		if (memcmp(&af1.ip1.v6, &af2.ip1.v6, sizeof(af1.ip1.v6)) == 0 &&
		    memcmp(&af1.ip2.v6, &af2.ip2.v6, sizeof(af1.ip2.v6)) == 0 &&
		    af1.port1 == af2.port1 && af1.port2 == af2.port2)
			return 1;
		if (memcmp(&af1.ip1.v6, &af2.ip2.v6, sizeof(af1.ip1.v6)) == 0 &&
		    memcmp(&af1.ip2.v6, &af2.ip1.v6, sizeof(af1.ip2.v6)) == 0 &&
		    af1.port1 == af2.port2 && af1.port2 == af2.port1)
			return 1;
		break;
	}

	return 0;
}

struct ip_pair *find_ip_pair(struct af_6tuple af_6tuple)
{
	struct ip_pair *p;
	unsigned int hash;

	hash = hash_5tuple(af_6tuple);
	if (pairs[hash]) {
		for (p = pairs [hash]; p != NULL; p = p->next) {
			if (compare_5tuple(p->af_6tuple, af_6tuple))
				return p;
		}
	}

	return NULL;
}

struct ip_pair *register_ip_pair(struct af_6tuple af_6tuple)
{
	struct ip_pair *newp;
	unsigned int hash;

	hash = hash_5tuple(af_6tuple);

	newp = (struct ip_pair *)malloc(sizeof(struct ip_pair));
	if (!newp) {
		fprintf(stderr, "not enough memory to allocate another IP pair\n");
		exit(1);
	}

	newp->af_6tuple = af_6tuple;
	newp->pdf.file_name = NULL;
	newp->next = pairs [hash];
	pairs [hash] = newp;
	reset_pdf((struct pkt_dump_file *) & (newp->pdf));

	return newp;
}
