#include "test_pkt2flow_base.cpp"

class Pkt2FlowUdpIntegrationTest : public Pkt2FlowBaseTest {
protected:
  void SetUp() override {
    Pkt2FlowBaseTest::SetUp();
    // UDP tests don't need special setup
  }
};

TEST_F(Pkt2FlowUdpIntegrationTest, ProcessValidUdpPcapFile) {
  // Test parameters
  std::string sample_file = "../sample/tpncp_udp.pcap";

  // Check if sample file exists
  struct stat st;
  if (stat(sample_file.c_str(), &st) != 0) {
    GTEST_SKIP() << "Valid UDP pcap file not found: " << sample_file;
  }

  // Process the file with UDP flag enabled
  bool success = process_pcap_file(sample_file, DUMP_UDP_ALLOWED);
  EXPECT_TRUE(success) << "Failed to process UDP pcap file";

  // Validate UDP flows
  std::string udp_dir = test_output_dir + "/udp";
  validate_flow_directory(udp_dir, "UDP");

  int udp_files = count_files_in_directory(udp_dir);
  EXPECT_GT(udp_files, 0) << "Should create at least one UDP flow file";
  LOG(INFO) << "Created " << udp_files << " UDP flow files";

  // Validate total flow count
  int total_flows = get_total_flow_count();
  EXPECT_GT(total_flows, 0) << "Should create at least one flow file";
  LOG(INFO) << "Total flow files created: " << total_flows;

  // Verify that other directories are empty (since this is UDP-only)
  std::vector<std::string> other_dirs = {"tcp_syn", "tcp_nosyn", "others"};
  for (const auto &dir : other_dirs) {
    std::string dir_path = test_output_dir + "/" + dir;
    if (stat(dir_path.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
      int files_in_dir = count_files_in_directory(dir_path);
      EXPECT_EQ(files_in_dir, 0)
          << "Directory " << dir << " should be empty for UDP-only file";
    }
  }
}

TEST_F(Pkt2FlowUdpIntegrationTest, UdpWithoutUdpFlag) {
  // Test that UDP files are ignored when -u flag is not provided
  std::string sample_file = "../sample/tpncp_udp.pcap";

  // Check if sample file exists
  struct stat st;
  if (stat(sample_file.c_str(), &st) != 0) {
    GTEST_SKIP() << "UDP pcap file not found: " << sample_file;
  }

  // Process the file WITHOUT UDP flag
  bool success = process_pcap_file(sample_file, 0);
  EXPECT_TRUE(success) << "Failed to process UDP pcap file";

  // Check that UDP directory should be empty
  std::string udp_dir = test_output_dir + "/udp";
  struct stat dir_st;
  if (stat(udp_dir.c_str(), &dir_st) == 0 && S_ISDIR(dir_st.st_mode)) {
    int udp_files = count_files_in_directory(udp_dir);
    EXPECT_EQ(udp_files, 0)
        << "UDP flows should be ignored when -u flag is not provided";
  }

  // Check that other directories are also empty (since this is UDP-only file)
  std::vector<std::string> other_dirs = {"tcp_syn", "tcp_nosyn", "others"};
  for (const auto &dir : other_dirs) {
    std::string dir_path = test_output_dir + "/" + dir;
    if (stat(dir_path.c_str(), &dir_st) == 0 && S_ISDIR(dir_st.st_mode)) {
      int files_in_dir = count_files_in_directory(dir_path);
      EXPECT_EQ(files_in_dir, 0)
          << "Directory " << dir
          << " should be empty for UDP-only file without -u flag";
    }
  }
}

TEST_F(Pkt2FlowUdpIntegrationTest, ValidateUdpFlowFileNames) {
  // Test parameters
  std::string sample_file = "../sample/tpncp_udp.pcap";

  // Check if sample file exists
  struct stat st;
  if (stat(sample_file.c_str(), &st) != 0) {
    GTEST_SKIP() << "UDP pcap file not found: " << sample_file;
  }

  // Process the file
  bool success = process_pcap_file(sample_file, DUMP_UDP_ALLOWED);
  EXPECT_TRUE(success) << "Failed to process UDP pcap file";

  // Validate file naming convention for UDP flows
  std::string udp_dir = test_output_dir + "/udp";
  DIR *dir_ptr = opendir(udp_dir.c_str());
  if (dir_ptr) {
    struct dirent *entry;
    while ((entry = readdir(dir_ptr)) != nullptr) {
      if (entry->d_type == DT_REG) {
        std::string filename = entry->d_name;

        // Check file extension
        EXPECT_TRUE(filename.find(".pcap") != std::string::npos)
            << "UDP flow file should have .pcap extension: " << filename;

        // Check that filename contains IP addresses and ports
        EXPECT_TRUE(filename.find("_") != std::string::npos)
            << "UDP flow filename should contain underscores: " << filename;

        // Check that filename contains expected IP patterns
        EXPECT_TRUE(filename.find("10.4.") != std::string::npos)
            << "UDP flow filename should contain IP addresses: " << filename;
      }
    }
    closedir(dir_ptr);
  }
}
