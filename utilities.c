
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
	 
#define IP_LENGTH sizeof("aaa.bbb.ccc.ddd")
#define FILE_NAME_LEGNTH 64

char *ip_ntos(unsigned long n)
{
	char *buf = (char *)malloc(IP_LENGTH);
	memset(buf, '\0', IP_LENGTH);
	sprintf(buf, "%d.%d.%d.%d",
		(n & 0xff000000) >> 24,
		(n & 0x00ff0000) >> 16,
		(n & 0x0000ff00) >> 8,
		(n & 0x000000ff) >> 0);
	return buf;
}
 
char *new_file_name(src_ip, dst_ip, src_tcp, dst_tcp, timestamp)
unsigned int src_ip, dst_ip;
unsigned short src_tcp, dst_tcp;
unsigned long timestamp;
{
	char *src_ip_str = ip_ntos(src_ip);
	char *dst_ip_str = ip_ntos(dst_ip);
	char *fname = (char *)malloc(FILE_NAME_LEGNTH);
	memset(fname, '\0', FILE_NAME_LEGNTH);
	sprintf(fname, "%s_%d_%s_%d_%d.pcap", src_ip_str, src_tcp, dst_ip_str, dst_tcp, timestamp);
	//fprintf(stderr, "%s\n", buf);
	free(src_ip_str);
	free(dst_ip_str);
	return fname;
}