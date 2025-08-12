#include "test_pkt2flow_base.cpp"

class Pkt2FlowTcpIntegrationTest : public Pkt2FlowBaseTest {
protected:
  void SetUp() override {
    Pkt2FlowBaseTest::SetUp();
    // TCP tests don't need special setup
  }
};

TEST_F(Pkt2FlowTcpIntegrationTest, ProcessTcpSynPcapFile) {
  // Test parameters
  std::string sample_file = "../sample/200722_win_scale_examples_anon.pcapng";

  // Check if sample file exists
  struct stat st;
  if (stat(sample_file.c_str(), &st) != 0) {
    GTEST_SKIP() << "TCP pcap file not found: " << sample_file;
  }

  // Process the file with TCP flags (default behavior)
  bool success = process_pcap_file(sample_file, DUMP_TCP_NOSYN_ALLOWED);
  EXPECT_TRUE(success) << "Failed to process TCP pcap file";

  // Validate TCP SYN flows
  std::string tcp_syn_dir = test_output_dir + "/tcp_syn";
  validate_flow_directory(tcp_syn_dir, "TCP SYN");

  int tcp_syn_files = count_files_in_directory(tcp_syn_dir);
  EXPECT_GT(tcp_syn_files, 0) << "Should create at least one TCP SYN flow file";
  LOG(INFO) << "Created " << tcp_syn_files << " TCP SYN flow files";

  // Validate total flow count
  int total_flows = get_total_flow_count();
  EXPECT_GT(total_flows, 0) << "Should create at least one flow file";
  LOG(INFO) << "Total flow files created: " << total_flows;
}

TEST_F(Pkt2FlowTcpIntegrationTest, TcpWithoutTcpNoSynFlag) {
  // Test that TCP flows without SYN are ignored when -v flag is not provided
  std::string sample_file = "../sample/200722_win_scale_examples_anon.pcapng";

  // Check if sample file exists
  struct stat st;
  if (stat(sample_file.c_str(), &st) != 0) {
    GTEST_SKIP() << "TCP pcap file not found: " << sample_file;
  }

  // Process the file without TCP NOSYN flag
  bool success = process_pcap_file(sample_file, 0);
  EXPECT_TRUE(success) << "Failed to process TCP pcap file";

  // Check that tcp_nosyn directory should be empty
  std::string tcp_nosyn_dir = test_output_dir + "/tcp_nosyn";
  struct stat dir_st;
  if (stat(tcp_nosyn_dir.c_str(), &dir_st) == 0 && S_ISDIR(dir_st.st_mode)) {
    int tcp_nosyn_files = count_files_in_directory(tcp_nosyn_dir);
    EXPECT_EQ(tcp_nosyn_files, 0)
        << "TCP NOSYN flows should be ignored when flag is not provided";
  }

  // TCP SYN flows should still be created (they don't require special flags)
  std::string tcp_syn_dir = test_output_dir + "/tcp_syn";
  int tcp_syn_files = count_files_in_directory(tcp_syn_dir);
  EXPECT_GT(tcp_syn_files, 0) << "TCP SYN flows should still be created";
}

TEST_F(Pkt2FlowTcpIntegrationTest, ValidateTcpFlowFileNames) {
  // Test parameters
  std::string sample_file = "../sample/200722_win_scale_examples_anon.pcapng";

  // Check if sample file exists
  struct stat st;
  if (stat(sample_file.c_str(), &st) != 0) {
    GTEST_SKIP() << "TCP pcap file not found: " << sample_file;
  }

  // Process the file
  bool success = process_pcap_file(sample_file, DUMP_TCP_NOSYN_ALLOWED);
  EXPECT_TRUE(success) << "Failed to process TCP pcap file";

  // Validate file naming convention for TCP flows
  std::vector<std::string> flow_dirs = {"tcp_syn", "tcp_nosyn"};
  for (const auto &dir : flow_dirs) {
    std::string dir_path = test_output_dir + "/" + dir;
    DIR *dir_ptr = opendir(dir_path.c_str());
    if (dir_ptr) {
      struct dirent *entry;
      while ((entry = readdir(dir_ptr)) != nullptr) {
        if (entry->d_type == DT_REG) {
          std::string filename = entry->d_name;

          // Check file extension
          EXPECT_TRUE(filename.find(".pcap") != std::string::npos)
              << "TCP flow file should have .pcap extension: " << filename;

          // Check that filename contains IP addresses and ports
          EXPECT_TRUE(filename.find("_") != std::string::npos)
              << "TCP flow filename should contain underscores: " << filename;

          // Check that filename contains timestamp
          EXPECT_TRUE(filename.find("1595") != std::string::npos)
              << "TCP flow filename should contain timestamp: " << filename;
        }
      }
      closedir(dir_ptr);
    }
  }
}
