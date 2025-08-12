#include "pkt2flow.h"
#include <stdio.h>
#include <string.h>

int main(void) {
  // Initialize the hash table
  init_hash_table();

  // Create a 6-tuple for a flow (IPv4, TCP, src: 1.2.3.4:1234, dst: 5.6.7.8:80)
  struct af_6tuple tuple;
  memset(&tuple, 0, sizeof(tuple));
  tuple.af_family = AF_INET;
  tuple.protocol = 6;               // TCP
  tuple.ip1.v4.s_addr = 0x04030201; // 1.2.3.4
  tuple.ip2.v4.s_addr = 0x08070605; // 5.6.7.8
  tuple.port1 = 1234;
  tuple.port2 = 80;
  tuple.is_vlan = 0;

  // Register the flow
  struct ip_pair *pair = register_ip_pair(tuple);
  if (pair) {
    printf("Flow registered: src=%x:%u dst=%x:%u\n",
           pair->af_6tuple.ip1.v4.s_addr, pair->af_6tuple.port1,
           pair->af_6tuple.ip2.v4.s_addr, pair->af_6tuple.port2);
  }

  // Find the flow
  struct ip_pair *found = find_ip_pair(tuple);
  if (found) {
    printf("Flow found!\n");
  } else {
    printf("Flow not found!\n");
  }

  // Reset the flow's packet dump file
  reset_pdf(&pair->pdf);

  // Free the hash table
  free_hash_table();

  return 0;
}