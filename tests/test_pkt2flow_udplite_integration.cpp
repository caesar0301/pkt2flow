#include "test_pkt2flow_base.cpp"

class Pkt2FlowUdpLiteIntegrationTest : public Pkt2FlowBaseTest {
protected:
  void SetUp() override {
    Pkt2FlowBaseTest::SetUp();
    // UDP-Lite tests don't need special setup
  }
};

TEST_F(Pkt2FlowUdpLiteIntegrationTest, ProcessNormalUdpLitePcapFile) {
  // Test parameters - UDP-Lite packets (protocol 136) should be treated as
  // "other"
  std::string sample_file = "../sample/udp_lite_normal_coverage_8-20.pcap";

  // Check if sample file exists
  struct stat st;
  if (stat(sample_file.c_str(), &st) != 0) {
    GTEST_SKIP() << "Normal UDP-Lite pcap file not found: " << sample_file;
  }

  // Process the file with UDP and other protocols flags enabled (UDP-Lite
  // should be treated as "other")
  bool success =
      process_pcap_file(sample_file, DUMP_UDP_ALLOWED | DUMP_OTHER_ALLOWED);
  EXPECT_TRUE(success) << "Failed to process UDP-Lite pcap file";

  // Validate "others" flows (UDP-Lite is not UDP)
  std::string others_dir = test_output_dir + "/others";
  validate_flow_directory(others_dir, "UDP-Lite");

  int others_files = count_files_in_directory(others_dir);
  EXPECT_GT(others_files, 0)
      << "Should create at least one flow file for UDP-Lite packets";
  LOG(INFO) << "Created " << others_files << " flow files for UDP-Lite packets";

  // Validate total flow count
  int total_flows = get_total_flow_count();
  EXPECT_GT(total_flows, 0) << "Should create at least one flow file";
  LOG(INFO) << "Total flow files created: " << total_flows;

  // Verify that UDP directory is empty (since UDP-Lite is not UDP)
  std::string udp_dir = test_output_dir + "/udp";
  if (stat(udp_dir.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
    int udp_files = count_files_in_directory(udp_dir);
    EXPECT_EQ(udp_files, 0)
        << "UDP directory should be empty for UDP-Lite packets";
  }

  // Verify that TCP directories are empty
  std::vector<std::string> tcp_dirs = {"tcp_syn", "tcp_nosyn"};
  for (const auto &dir : tcp_dirs) {
    std::string dir_path = test_output_dir + "/" + dir;
    if (stat(dir_path.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
      int files_in_dir = count_files_in_directory(dir_path);
      EXPECT_EQ(files_in_dir, 0)
          << "Directory " << dir << " should be empty for UDP-Lite file";
    }
  }
}

TEST_F(Pkt2FlowUdpLiteIntegrationTest, ProcessIllegalUdpLitePcapFile) {
  // Test parameters - UDP-Lite packets (protocol 136) should be treated as
  // "other"
  std::string sample_file = "../sample/udp_lite_illegal_large-coverage.pcap";

  // Check if sample file exists
  struct stat st;
  if (stat(sample_file.c_str(), &st) != 0) {
    GTEST_SKIP() << "Illegal UDP-Lite pcap file not found: " << sample_file;
  }

  // Process the file with UDP and other protocols flags enabled (UDP-Lite
  // should be treated as "other")
  bool success =
      process_pcap_file(sample_file, DUMP_UDP_ALLOWED | DUMP_OTHER_ALLOWED);
  EXPECT_TRUE(success) << "Failed to process illegal UDP-Lite pcap file";

  // Validate "others" flows (UDP-Lite is not UDP)
  std::string others_dir = test_output_dir + "/others";
  validate_flow_directory(others_dir, "Illegal UDP-Lite");

  int others_files = count_files_in_directory(others_dir);
  EXPECT_GT(others_files, 0)
      << "Should create at least one flow file for illegal UDP-Lite packets";
  LOG(INFO) << "Created " << others_files
            << " flow files for illegal UDP-Lite packets";

  // Validate total flow count
  int total_flows = get_total_flow_count();
  EXPECT_GT(total_flows, 0) << "Should create at least one flow file";
  LOG(INFO) << "Total flow files created: " << total_flows;
}

TEST_F(Pkt2FlowUdpLiteIntegrationTest, CompareUdpLiteFileHandling) {
  // Test to compare handling of normal vs illegal UDP-Lite files
  std::string normal_file = "../sample/udp_lite_normal_coverage_8-20.pcap";
  std::string illegal_file = "../sample/udp_lite_illegal_large-coverage.pcap";

  // Check if both files exist
  struct stat st;
  if (stat(normal_file.c_str(), &st) != 0 ||
      stat(illegal_file.c_str(), &st) != 0) {
    GTEST_SKIP() << "One or both UDP-Lite pcap files not found";
  }

  // Process normal UDP-Lite file
  bool normal_success =
      process_pcap_file(normal_file, DUMP_UDP_ALLOWED | DUMP_OTHER_ALLOWED);
  EXPECT_TRUE(normal_success) << "Failed to process normal UDP-Lite file";

  int normal_flows = count_files_in_directory(test_output_dir + "/others");
  LOG(INFO) << "Normal UDP-Lite file created " << normal_flows << " flows";
  EXPECT_GT(normal_flows, 0) << "Normal UDP-Lite file should create flows";

  // Clean up and process illegal UDP-Lite file
  cleanup_directory(test_output_dir);

  bool illegal_success =
      process_pcap_file(illegal_file, DUMP_UDP_ALLOWED | DUMP_OTHER_ALLOWED);
  EXPECT_TRUE(illegal_success) << "Failed to process illegal UDP-Lite file";

  int illegal_flows = count_files_in_directory(test_output_dir + "/others");
  LOG(INFO) << "Illegal UDP-Lite file created " << illegal_flows << " flows";
  EXPECT_GT(illegal_flows, 0) << "Illegal UDP-Lite file should create flows";
}

TEST_F(Pkt2FlowUdpLiteIntegrationTest, UdpLiteWithoutOtherFlag) {
  // Test that UDP-Lite files are ignored when -x flag is not provided
  std::string sample_file = "../sample/udp_lite_normal_coverage_8-20.pcap";

  // Check if sample file exists
  struct stat st;
  if (stat(sample_file.c_str(), &st) != 0) {
    GTEST_SKIP() << "UDP-Lite pcap file not found: " << sample_file;
  }

  // Process the file WITHOUT other protocols flag (only UDP flag)
  bool success = process_pcap_file(sample_file, DUMP_UDP_ALLOWED);
  EXPECT_TRUE(success) << "Failed to process UDP-Lite pcap file";

  // Check that "others" directory should be empty (UDP-Lite should be ignored
  // without -x flag)
  std::string others_dir = test_output_dir + "/others";
  struct stat dir_st;
  if (stat(others_dir.c_str(), &dir_st) == 0 && S_ISDIR(dir_st.st_mode)) {
    int others_files = count_files_in_directory(others_dir);
    EXPECT_EQ(others_files, 0)
        << "UDP-Lite flows should be ignored when -x flag is not provided";
  }

  // Check that other directories are also empty (since this is UDP-Lite-only
  // file)
  std::vector<std::string> other_dirs = {"tcp_syn", "tcp_nosyn", "udp"};
  for (const auto &dir : other_dirs) {
    std::string dir_path = test_output_dir + "/" + dir;
    if (stat(dir_path.c_str(), &dir_st) == 0 && S_ISDIR(dir_st.st_mode)) {
      int files_in_dir = count_files_in_directory(dir_path);
      EXPECT_EQ(files_in_dir, 0)
          << "Directory " << dir
          << " should be empty for UDP-Lite-only file without -x flag";
    }
  }
}

TEST_F(Pkt2FlowUdpLiteIntegrationTest, ValidateUdpLiteFlowFileNames) {
  // Test parameters
  std::string sample_file = "../sample/udp_lite_normal_coverage_8-20.pcap";

  // Check if sample file exists
  struct stat st;
  if (stat(sample_file.c_str(), &st) != 0) {
    GTEST_SKIP() << "UDP-Lite pcap file not found: " << sample_file;
  }

  // Process the file
  bool success =
      process_pcap_file(sample_file, DUMP_UDP_ALLOWED | DUMP_OTHER_ALLOWED);
  EXPECT_TRUE(success) << "Failed to process UDP-Lite pcap file";

  // Validate file naming convention for UDP-Lite flows
  std::string others_dir = test_output_dir + "/others";
  DIR *dir_ptr = opendir(others_dir.c_str());
  if (dir_ptr) {
    struct dirent *entry;
    while ((entry = readdir(dir_ptr)) != nullptr) {
      if (entry->d_type == DT_REG) {
        std::string filename = entry->d_name;

        // Check file extension
        EXPECT_TRUE(filename.find(".pcap") != std::string::npos)
            << "UDP-Lite flow file should have .pcap extension: " << filename;

        // Check that filename contains IP addresses and ports
        EXPECT_TRUE(filename.find("_") != std::string::npos)
            << "UDP-Lite flow filename should contain underscores: "
            << filename;

        // Check that filename contains expected IP patterns
        EXPECT_TRUE(filename.find("139.133.204") != std::string::npos)
            << "UDP-Lite flow filename should contain IP addresses: "
            << filename;
      }
    }
    closedir(dir_ptr);
  }
}
