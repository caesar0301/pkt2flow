#include <arpa/inet.h>
#include <cstring>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <netinet/in.h>

extern "C" {
#include "pkt2flow.h"
}

class FlowDbTest : public ::testing::Test {
protected:
  void SetUp() override { init_hash_table(); }

  void TearDown() override { free_hash_table(); }

  struct af_6tuple create_test_tuple_ipv4(const char *src_ip, uint16_t src_port,
                                          const char *dst_ip, uint16_t dst_port,
                                          int protocol = IPPROTO_TCP) {
    struct af_6tuple tuple;
    memset(&tuple, 0, sizeof(tuple));

    tuple.af_family = AF_INET;
    tuple.protocol = protocol;
    tuple.port1 = src_port;
    tuple.port2 = dst_port;
    tuple.is_vlan = 0;

    inet_pton(AF_INET, src_ip, &tuple.ip1.v4);
    inet_pton(AF_INET, dst_ip, &tuple.ip2.v4);

    return tuple;
  }
};

TEST_F(FlowDbTest, InitHashTable) {
  // Hash table should be initialized with NULL pointers
  for (int i = 0; i < HASH_TBL_SIZE; i++) {
    extern struct ip_pair *pairs[];
    EXPECT_EQ(pairs[i], nullptr);
  }
}

TEST_F(FlowDbTest, RegisterAndFindIpPair) {
  // Create a test tuple
  auto tuple = create_test_tuple_ipv4("192.168.1.1", 80, "192.168.1.2", 8080);

  // Initially, the pair should not exist
  struct ip_pair *pair = find_ip_pair(tuple);
  EXPECT_EQ(pair, nullptr);

  // Register the pair
  pair = register_ip_pair(tuple);
  EXPECT_NE(pair, nullptr);
  EXPECT_EQ(pair->af_6tuple.af_family, AF_INET);
  EXPECT_EQ(pair->af_6tuple.protocol, IPPROTO_TCP);
  EXPECT_EQ(pair->af_6tuple.port1, 80);
  EXPECT_EQ(pair->af_6tuple.port2, 8080);

  // Now we should be able to find it
  struct ip_pair *found_pair = find_ip_pair(tuple);
  EXPECT_EQ(found_pair, pair);
}

TEST_F(FlowDbTest, BidirectionalFlow) {
  // Create forward tuple
  auto forward_tuple =
      create_test_tuple_ipv4("192.168.1.1", 80, "192.168.1.2", 8080);

  // Create reverse tuple (swapped IPs and ports)
  auto reverse_tuple =
      create_test_tuple_ipv4("192.168.1.2", 8080, "192.168.1.1", 80);

  // Register forward flow
  struct ip_pair *forward_pair = register_ip_pair(forward_tuple);
  EXPECT_NE(forward_pair, nullptr);

  // Finding with reverse tuple should return the same pair (bidirectional)
  struct ip_pair *reverse_pair = find_ip_pair(reverse_tuple);
  EXPECT_EQ(forward_pair, reverse_pair);
}

TEST_F(FlowDbTest, MultipleFlows) {
  // Create multiple different flows
  auto tuple1 = create_test_tuple_ipv4("192.168.1.1", 80, "192.168.1.2", 8080);
  auto tuple2 = create_test_tuple_ipv4("192.168.1.3", 443, "192.168.1.4", 9090);
  auto tuple3 =
      create_test_tuple_ipv4("10.0.0.1", 22, "10.0.0.2", 2222, IPPROTO_UDP);

  // Register all flows
  struct ip_pair *pair1 = register_ip_pair(tuple1);
  struct ip_pair *pair2 = register_ip_pair(tuple2);
  struct ip_pair *pair3 = register_ip_pair(tuple3);

  EXPECT_NE(pair1, nullptr);
  EXPECT_NE(pair2, nullptr);
  EXPECT_NE(pair3, nullptr);

  // All pairs should be different
  EXPECT_NE(pair1, pair2);
  EXPECT_NE(pair1, pair3);
  EXPECT_NE(pair2, pair3);

  // Find each flow
  EXPECT_EQ(find_ip_pair(tuple1), pair1);
  EXPECT_EQ(find_ip_pair(tuple2), pair2);
  EXPECT_EQ(find_ip_pair(tuple3), pair3);
}

TEST_F(FlowDbTest, ResetPdf) {
  struct pkt_dump_file pdf;
  pdf.pkts = 100;
  pdf.start_time = 12345;
  pdf.status = STS_TCP_SYN;
  pdf.file_name = strdup("test_file.pcap");
  pdf.dumper = nullptr; // Initialize dumper to nullptr

  reset_pdf(&pdf);

  EXPECT_EQ(pdf.pkts, 0);
  EXPECT_EQ(pdf.start_time, 0);
  EXPECT_EQ(pdf.status, STS_UNSET);
  EXPECT_EQ(pdf.file_name, nullptr);
  EXPECT_EQ(pdf.dumper, nullptr);
}

TEST_F(FlowDbTest, UdpFlow) {
  auto udp_tuple =
      create_test_tuple_ipv4("192.168.1.1", 53, "8.8.8.8", 53, IPPROTO_UDP);

  struct ip_pair *pair = register_ip_pair(udp_tuple);
  EXPECT_NE(pair, nullptr);
  EXPECT_EQ(pair->af_6tuple.protocol, IPPROTO_UDP);

  struct ip_pair *found_pair = find_ip_pair(udp_tuple);
  EXPECT_EQ(found_pair, pair);
}