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
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

static void usage(char *progname) {
  fprintf(stderr, "Name: %s\n", __GLOBAL_NAME__);
  fprintf(stderr, "Version: %s\n", __SOURCE_VERSION__);
  fprintf(stderr, "Author: %s\n", __AUTHOR__);
  fprintf(stderr,
          "Program to seperate the packets into flows (UDP or TCP).\n\n");
  fprintf(stderr, "Usage: %s [-huvx] [-o outdir] pcapfile\n\n", progname);
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "	-h	print this help and exit\n");
  fprintf(stderr, "	-u	also dump (U)DP flows\n");
  fprintf(
      stderr,
      "	-v	also dump the in(v)alid TCP flows without the SYN option\n");
  fprintf(stderr, "	-x	also dump non-UDP/non-TCP IP flows\n");
  fprintf(stderr, "	-o	(o)utput directory\n");
}

static void parseargs(int argc, char *argv[]) {
  int opt;
  const char *optstr = "uvxo:h";
  uint32_t dump_flags = 0;
  char *readfile = NULL;

  while ((opt = getopt(argc, argv, optstr)) != -1) {
    switch (opt) {
    case 'h':
      usage(argv[0]);
      exit(-1);
    case 'o':
      set_outputdir(optarg);
      break;
    case 'u':
      dump_flags |= DUMP_UDP_ALLOWED;
      break;
    case 'v':
      dump_flags |= DUMP_TCP_NOSYN_ALLOWED;
      break;
    case 'x':
      dump_flags |= DUMP_OTHER_ALLOWED;
      break;
    default:
      usage(argv[0]);
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

  // Set the configuration using the library functions
  set_readfile(readfile);
  set_dump_allowed(dump_flags);
}

int main(int argc, char *argv[]) {
  parseargs(argc, argv);
  open_trace_file();
  init_hash_table();
  process_trace();
  close_trace_files();
  free_hash_table();
  exit(0);
}
