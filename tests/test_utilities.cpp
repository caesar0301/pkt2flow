#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <netinet/in.h>

extern "C" {
#include "pkt2flow.h"
}

class UtilitiesTest : public ::testing::Test {
protected:
  struct af_6tuple create_test_tuple_ipv4(const char *src_ip, uint16_t src_port,
                                          const char *dst_ip, uint16_t dst_port,
                                          int protocol = IPPROTO_TCP,
                                          uint8_t is_vlan = 0) {
    struct af_6tuple tuple;
    memset(&tuple, 0, sizeof(tuple));

    tuple.af_family = AF_INET;
    tuple.protocol = protocol;
    tuple.port1 = src_port;
    tuple.port2 = dst_port;
    tuple.is_vlan = is_vlan;

    inet_pton(AF_INET, src_ip, &tuple.ip1.v4);
    inet_pton(AF_INET, dst_ip, &tuple.ip2.v4);

    return tuple;
  }

  struct af_6tuple create_test_tuple_ipv6(const char *src_ip, uint16_t src_port,
                                          const char *dst_ip, uint16_t dst_port,
                                          int protocol = IPPROTO_TCP,
                                          uint8_t is_vlan = 0) {
    struct af_6tuple tuple;
    memset(&tuple, 0, sizeof(tuple));

    tuple.af_family = AF_INET6;
    tuple.protocol = protocol;
    tuple.port1 = src_port;
    tuple.port2 = dst_port;
    tuple.is_vlan = is_vlan;

    inet_pton(AF_INET6, src_ip, &tuple.ip1.v6);
    inet_pton(AF_INET6, dst_ip, &tuple.ip2.v6);

    return tuple;
  }
};

TEST_F(UtilitiesTest, NewFileNameIPv4) {
  auto tuple = create_test_tuple_ipv4("192.168.1.1", 80, "192.168.1.2", 8080);
  unsigned long timestamp = 1234567890;

  char *filename = new_file_name(tuple, timestamp);
  ASSERT_NE(filename, nullptr);

  // Check that filename contains expected components
  EXPECT_TRUE(strstr(filename, "192.168.1.1") != nullptr);
  EXPECT_TRUE(strstr(filename, "192.168.1.2") != nullptr);
  EXPECT_TRUE(strstr(filename, "80") != nullptr);
  EXPECT_TRUE(strstr(filename, "8080") != nullptr);
  EXPECT_TRUE(strstr(filename, "1234567890") != nullptr);
  EXPECT_TRUE(strstr(filename, ".pcap") != nullptr);

  // Should not contain vlan suffix for non-VLAN traffic
  EXPECT_FALSE(strstr(filename, "_vlan.pcap") != nullptr);

  free(filename);
}

TEST_F(UtilitiesTest, NewFileNameIPv4WithVlan) {
  auto tuple =
      create_test_tuple_ipv4("10.0.0.1", 443, "10.0.0.2", 9090, IPPROTO_TCP, 1);
  unsigned long timestamp = 9876543210;

  char *filename = new_file_name(tuple, timestamp);
  ASSERT_NE(filename, nullptr);

  // Check that filename contains expected components including VLAN
  EXPECT_TRUE(strstr(filename, "10.0.0.1") != nullptr);
  EXPECT_TRUE(strstr(filename, "10.0.0.2") != nullptr);
  EXPECT_TRUE(strstr(filename, "443") != nullptr);
  EXPECT_TRUE(strstr(filename, "9090") != nullptr);
  EXPECT_TRUE(strstr(filename, "9876543210") != nullptr);
  EXPECT_TRUE(strstr(filename, "_vlan.pcap") != nullptr);

  free(filename);
}

TEST_F(UtilitiesTest, NewFileNameIPv6) {
  auto tuple = create_test_tuple_ipv6("2001:db8::1", 80, "2001:db8::2", 8080);
  unsigned long timestamp = 1111111111;

  char *filename = new_file_name(tuple, timestamp);
  ASSERT_NE(filename, nullptr);

  // Check that filename contains expected components
  EXPECT_TRUE(strstr(filename, "2001:db8::1") != nullptr);
  EXPECT_TRUE(strstr(filename, "2001:db8::2") != nullptr);
  EXPECT_TRUE(strstr(filename, "80") != nullptr);
  EXPECT_TRUE(strstr(filename, "8080") != nullptr);
  EXPECT_TRUE(strstr(filename, "1111111111") != nullptr);
  EXPECT_TRUE(strstr(filename, ".pcap") != nullptr);

  free(filename);
}

TEST_F(UtilitiesTest, NewFileNameIPv6WithVlan) {
  auto tuple =
      create_test_tuple_ipv6("fe80::1", 22, "fe80::2", 2222, IPPROTO_TCP, 1);
  unsigned long timestamp = 5555555555;

  char *filename = new_file_name(tuple, timestamp);
  ASSERT_NE(filename, nullptr);

  // Check that filename contains expected components including VLAN
  EXPECT_TRUE(strstr(filename, "fe80::1") != nullptr);
  EXPECT_TRUE(strstr(filename, "fe80::2") != nullptr);
  EXPECT_TRUE(strstr(filename, "22") != nullptr);
  EXPECT_TRUE(strstr(filename, "2222") != nullptr);
  EXPECT_TRUE(strstr(filename, "5555555555") != nullptr);
  EXPECT_TRUE(strstr(filename, "_vlan.pcap") != nullptr);

  free(filename);
}

TEST_F(UtilitiesTest, NewFileNameZeroPorts) {
  auto tuple =
      create_test_tuple_ipv4("172.16.0.1", 0, "172.16.0.2", 0, IPPROTO_UDP);
  unsigned long timestamp = 7777777777;

  char *filename = new_file_name(tuple, timestamp);
  ASSERT_NE(filename, nullptr);

  // Should handle zero ports gracefully
  EXPECT_TRUE(strstr(filename, "172.16.0.1") != nullptr);
  EXPECT_TRUE(strstr(filename, "172.16.0.2") != nullptr);
  EXPECT_TRUE(strstr(filename, "7777777777") != nullptr);
  EXPECT_TRUE(strstr(filename, ".pcap") != nullptr);

  free(filename);
}

TEST_F(UtilitiesTest, FileNameUniqueness) {
  auto tuple1 = create_test_tuple_ipv4("192.168.1.1", 80, "192.168.1.2", 8080);
  auto tuple2 = create_test_tuple_ipv4("192.168.1.1", 80, "192.168.1.3", 8080);
  unsigned long timestamp = 1234567890;

  char *filename1 = new_file_name(tuple1, timestamp);
  char *filename2 = new_file_name(tuple2, timestamp);

  ASSERT_NE(filename1, nullptr);
  ASSERT_NE(filename2, nullptr);

  // Different tuples should generate different filenames
  EXPECT_STRNE(filename1, filename2);

  free(filename1);
  free(filename2);
}

TEST_F(UtilitiesTest, FileNameTimestampDifference) {
  auto tuple = create_test_tuple_ipv4("192.168.1.1", 80, "192.168.1.2", 8080);
  unsigned long timestamp1 = 1234567890;
  unsigned long timestamp2 = 1234567891;

  char *filename1 = new_file_name(tuple, timestamp1);
  char *filename2 = new_file_name(tuple, timestamp2);

  ASSERT_NE(filename1, nullptr);
  ASSERT_NE(filename2, nullptr);

  // Different timestamps should generate different filenames
  EXPECT_STRNE(filename1, filename2);

  free(filename1);
  free(filename2);
}