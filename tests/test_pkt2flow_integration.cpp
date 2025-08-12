#include <algorithm>
#include <dirent.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

extern "C" {
#include "pkt2flow.h"
}

class Pkt2FlowIntegrationTest : public ::testing::Test {
protected:
  void SetUp() override {
    // Create a temporary output directory
    test_output_dir = "test_pkt2flow_out";
    mkdir(test_output_dir.c_str(), 0755);
  }

  void TearDown() override {
    // Clean up test output directory
    cleanup_directory(test_output_dir);
    rmdir(test_output_dir.c_str());
  }

  std::string test_output_dir;

  // Helper function to count files in a directory
  int count_files_in_directory(const std::string &dir_path) {
    DIR *dir = opendir(dir_path.c_str());
    if (!dir)
      return 0;

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
      if (entry->d_type == DT_REG) { // Regular file
        count++;
      }
    }
    closedir(dir);
    return count;
  }

  // Helper function to recursively clean up directory
  void cleanup_directory(const std::string &dir_path) {
    DIR *dir = opendir(dir_path.c_str());
    if (!dir)
      return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
      if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
        continue;
      }

      std::string full_path = dir_path + "/" + entry->d_name;
      if (entry->d_type == DT_DIR) {
        cleanup_directory(full_path);
        rmdir(full_path.c_str());
      } else {
        unlink(full_path.c_str());
      }
    }
    closedir(dir);
  }

  // Helper function to validate pcap file format using tcpdump
  bool validate_pcap_file(const std::string &file_path) {
    std::string tcpdump_cmd = "tcpdump -r " + file_path + " > /dev/null 2>&1";
    int result = system(tcpdump_cmd.c_str());
    if (result != 0) {
      LOG(ERROR) << "tcpdump failed to read pcap file: " << file_path;
      return false;
    }

    // Check file size to ensure it's not empty
    struct stat st;
    if (stat(file_path.c_str(), &st) != 0) {
      LOG(ERROR) << "Failed to stat file: " << file_path;
      return false;
    }

    if (st.st_size < 100) {
      LOG(ERROR) << "Pcap file too small: " << file_path;
      return false;
    }

    LOG(INFO) << "Validated pcap file: " << file_path
              << " (size: " << st.st_size << " bytes)";
    return true;
  }
};

TEST_F(Pkt2FlowIntegrationTest, ProcessNormalUdpLitePcapFile) {
  // Test parameters - UDP-Lite packets (protocol 136) should be treated as
  // "other"
  std::string sample_file = "../sample/udp_lite_normal_coverage_8-20.pcap";
  std::string output_dir = test_output_dir;

  // Check if sample file exists
  struct stat st;
  if (stat(sample_file.c_str(), &st) != 0) {
    GTEST_SKIP() << "Normal UDP-Lite pcap file not found: " << sample_file;
  }

  // Run pkt2flow with UDP and other protocols flags enabled (UDP-Lite should be
  // treated as "other")
  std::string command = "./pkt2flow -u -x -o " + output_dir + " " + sample_file;
  int result = system(command.c_str());
  EXPECT_EQ(result, 0) << "pkt2flow should exit successfully";

  // Check that "others" directory was created and contains files (UDP-Lite is
  // not UDP)
  std::string others_dir = output_dir + "/others";
  struct stat dir_st;
  EXPECT_EQ(stat(others_dir.c_str(), &dir_st), 0)
      << "Others directory should exist: " << others_dir;
  EXPECT_TRUE(S_ISDIR(dir_st.st_mode))
      << "Should be a directory: " << others_dir;

  // Count "others" flow files
  int others_files = count_files_in_directory(others_dir);
  EXPECT_GT(others_files, 0)
      << "Should create at least one flow file for UDP-Lite packets";
  LOG(INFO) << "Created " << others_files << " flow files for UDP-Lite packets";

  // Validate each pcap file
  DIR *dir_ptr = opendir(others_dir.c_str());
  if (dir_ptr) {
    struct dirent *entry;
    while ((entry = readdir(dir_ptr)) != nullptr) {
      if (entry->d_type == DT_REG) {
        std::string file_path = others_dir + "/" + entry->d_name;
        EXPECT_TRUE(validate_pcap_file(file_path))
            << "Invalid UDP-Lite pcap file: " << file_path;

        // Check file size
        struct stat file_st;
        if (stat(file_path.c_str(), &file_st) == 0) {
          EXPECT_GT(file_st.st_size, 100)
              << "UDP-Lite flow file should have reasonable size: "
              << file_path;
          EXPECT_LT(file_st.st_size, 100000)
              << "UDP-Lite flow file should not be unreasonably large: "
              << file_path;
        }

        // Validate filename contains expected patterns
        std::string filename = entry->d_name;
        EXPECT_TRUE(filename.find(".pcap") != std::string::npos)
            << "UDP-Lite flow file should have .pcap extension: " << filename;
        EXPECT_TRUE(filename.find("139.133.204") != std::string::npos)
            << "UDP-Lite flow filename should contain IP addresses: "
            << filename;
      }
    }
    closedir(dir_ptr);
  }

  // Verify that UDP directory is empty (since UDP-Lite is not UDP)
  std::string udp_dir = output_dir + "/udp";
  if (stat(udp_dir.c_str(), &dir_st) == 0 && S_ISDIR(dir_st.st_mode)) {
    int udp_files = count_files_in_directory(udp_dir);
    EXPECT_EQ(udp_files, 0)
        << "UDP directory should be empty for UDP-Lite packets";
  }

  // Verify that TCP directories are empty
  std::vector<std::string> tcp_dirs = {"tcp_syn", "tcp_nosyn"};
  for (const auto &dir : tcp_dirs) {
    std::string dir_path = output_dir + "/" + dir;
    if (stat(dir_path.c_str(), &dir_st) == 0 && S_ISDIR(dir_st.st_mode)) {
      int files_in_dir = count_files_in_directory(dir_path);
      EXPECT_EQ(files_in_dir, 0)
          << "Directory " << dir << " should be empty for UDP-Lite file";
    }
  }
}

TEST_F(Pkt2FlowIntegrationTest, ProcessIllegalUdpLitePcapFile) {
  // Test parameters - UDP-Lite packets (protocol 136) should be treated as
  // "other"
  std::string sample_file = "../sample/udp_lite_illegal_large-coverage.pcap";
  std::string output_dir = test_output_dir;

  // Check if sample file exists
  struct stat st;
  if (stat(sample_file.c_str(), &st) != 0) {
    GTEST_SKIP() << "Illegal UDP-Lite pcap file not found: " << sample_file;
  }

  // Run pkt2flow with UDP and other protocols flags enabled (UDP-Lite should be
  // treated as "other")
  std::string command = "./pkt2flow -u -x -o " + output_dir + " " + sample_file;
  int result = system(command.c_str());
  EXPECT_EQ(result, 0) << "pkt2flow should exit successfully";

  // Check that "others" directory was created (UDP-Lite is not UDP)
  std::string others_dir = output_dir + "/others";
  struct stat dir_st;
  EXPECT_EQ(stat(others_dir.c_str(), &dir_st), 0)
      << "Others directory should exist: " << others_dir;
  EXPECT_TRUE(S_ISDIR(dir_st.st_mode))
      << "Should be a directory: " << others_dir;

  // Count "others" flow files
  int others_files = count_files_in_directory(others_dir);
  EXPECT_GT(others_files, 0)
      << "Should create at least one flow file for illegal UDP-Lite packets";
  LOG(INFO) << "Created " << others_files
            << " flow files for illegal UDP-Lite packets";

  // Validate each pcap file
  DIR *dir_ptr = opendir(others_dir.c_str());
  if (dir_ptr) {
    struct dirent *entry;
    while ((entry = readdir(dir_ptr)) != nullptr) {
      if (entry->d_type == DT_REG) {
        std::string file_path = others_dir + "/" + entry->d_name;
        EXPECT_TRUE(validate_pcap_file(file_path))
            << "Invalid illegal UDP-Lite pcap file: " << file_path;

        // Check file size (illegal packets might be smaller)
        struct stat file_st;
        if (stat(file_path.c_str(), &file_st) == 0) {
          EXPECT_GT(file_st.st_size, 50)
              << "Illegal UDP-Lite flow file should have reasonable size: "
              << file_path;
          EXPECT_LT(file_st.st_size, 100000)
              << "Illegal UDP-Lite flow file should not be unreasonably large: "
              << file_path;
        }

        // Validate filename contains expected patterns
        std::string filename = entry->d_name;
        EXPECT_TRUE(filename.find(".pcap") != std::string::npos)
            << "Illegal UDP-Lite flow file should have .pcap extension: "
            << filename;
        EXPECT_TRUE(filename.find("139.133.204") != std::string::npos)
            << "Illegal UDP-Lite flow filename should contain IP addresses: "
            << filename;
      }
    }
    closedir(dir_ptr);
  }
}

TEST_F(Pkt2FlowIntegrationTest, CompareUdpLiteFileHandling) {
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
  std::string normal_output = test_output_dir + "_normal";
  mkdir(normal_output.c_str(), 0755);
  std::string normal_command =
      "./pkt2flow -u -x -o " + normal_output + " " + normal_file;
  int normal_result = system(normal_command.c_str());
  EXPECT_EQ(normal_result, 0)
      << "pkt2flow should exit successfully for normal UDP-Lite file";

  // Process illegal UDP-Lite file
  std::string illegal_output = test_output_dir + "_illegal";
  mkdir(illegal_output.c_str(), 0755);
  std::string illegal_command =
      "./pkt2flow -u -x -o " + illegal_output + " " + illegal_file;
  int illegal_result = system(illegal_command.c_str());
  EXPECT_EQ(illegal_result, 0)
      << "pkt2flow should exit successfully for illegal UDP-Lite file";

  // Compare flow counts (both should be in "others" directory)
  std::string normal_others_dir = normal_output + "/others";
  std::string illegal_others_dir = illegal_output + "/others";

  int normal_flows = count_files_in_directory(normal_others_dir);
  int illegal_flows = count_files_in_directory(illegal_others_dir);

  LOG(INFO) << "Normal UDP-Lite file created " << normal_flows << " flows";
  LOG(INFO) << "Illegal UDP-Lite file created " << illegal_flows << " flows";

  // Both should create at least one flow
  EXPECT_GT(normal_flows, 0) << "Normal UDP-Lite file should create flows";
  EXPECT_GT(illegal_flows, 0) << "Illegal UDP-Lite file should create flows";

  // Validate that both create valid pcap files
  DIR *normal_dir = opendir(normal_others_dir.c_str());
  if (normal_dir) {
    struct dirent *entry;
    while ((entry = readdir(normal_dir)) != nullptr) {
      if (entry->d_type == DT_REG) {
        std::string file_path = normal_others_dir + "/" + entry->d_name;
        EXPECT_TRUE(validate_pcap_file(file_path))
            << "Normal UDP-Lite file should be valid pcap: " << file_path;
      }
    }
    closedir(normal_dir);
  }

  DIR *illegal_dir = opendir(illegal_others_dir.c_str());
  if (illegal_dir) {
    struct dirent *entry;
    while ((entry = readdir(illegal_dir)) != nullptr) {
      if (entry->d_type == DT_REG) {
        std::string file_path = illegal_others_dir + "/" + entry->d_name;
        EXPECT_TRUE(validate_pcap_file(file_path))
            << "Illegal UDP-Lite file should be valid pcap: " << file_path;
      }
    }
    closedir(illegal_dir);
  }

  // Clean up test directories
  cleanup_directory(normal_output);
  rmdir(normal_output.c_str());
  cleanup_directory(illegal_output);
  rmdir(illegal_output.c_str());
}

TEST_F(Pkt2FlowIntegrationTest, UdpLiteWithoutUdpFlag) {
  // Test that UDP-Lite files are ignored when -u flag is not provided
  std::string sample_file = "../sample/udp_lite_normal_coverage_8-20.pcap";
  std::string output_dir = test_output_dir;

  // Check if sample file exists
  struct stat st;
  if (stat(sample_file.c_str(), &st) != 0) {
    GTEST_SKIP() << "UDP-Lite pcap file not found: " << sample_file;
  }

  // Run pkt2flow WITHOUT UDP flag
  std::string command = "./pkt2flow -o " + output_dir + " " + sample_file;
  int result = system(command.c_str());
  EXPECT_EQ(result, 0) << "pkt2flow should exit successfully";

  // Check that "others" directory should be empty (UDP-Lite should be ignored
  // without -u flag)
  std::string others_dir = output_dir + "/others";
  struct stat dir_st;
  if (stat(others_dir.c_str(), &dir_st) == 0 && S_ISDIR(dir_st.st_mode)) {
    int others_files = count_files_in_directory(others_dir);
    EXPECT_EQ(others_files, 0)
        << "UDP-Lite flows should be ignored when -u flag is not provided";
  }

  // Check that other directories are also empty (since this is UDP-Lite-only
  // file)
  std::vector<std::string> other_dirs = {"tcp_syn", "tcp_nosyn", "udp"};
  for (const auto &dir : other_dirs) {
    std::string dir_path = output_dir + "/" + dir;
    if (stat(dir_path.c_str(), &dir_st) == 0 && S_ISDIR(dir_st.st_mode)) {
      int files_in_dir = count_files_in_directory(dir_path);
      EXPECT_EQ(files_in_dir, 0)
          << "Directory " << dir
          << " should be empty for UDP-Lite-only file without -u flag";
    }
  }
}

TEST_F(Pkt2FlowIntegrationTest, ProcessSamplePcapFile) {
  // Test parameters
  std::string sample_file = "../sample/200722_win_scale_examples_anon.pcapng";
  std::string output_dir = test_output_dir;

  // Check if sample file exists
  struct stat st;
  if (stat(sample_file.c_str(), &st) != 0) {
    GTEST_SKIP() << "Sample pcap file not found: " << sample_file;
  }

  // Run pkt2flow with UDP flag enabled
  std::string command = "./pkt2flow -u -o " + output_dir + " " + sample_file;
  int result = system(command.c_str());
  EXPECT_EQ(result, 0) << "pkt2flow should exit successfully";

  // Check that output directories were created (only those that contain files)
  std::vector<std::string> all_dirs = {"tcp_syn", "tcp_nosyn", "udp", "others"};
  std::vector<std::string> existing_dirs;

  for (const auto &dir : all_dirs) {
    std::string dir_path = output_dir + "/" + dir;
    struct stat dir_st;
    if (stat(dir_path.c_str(), &dir_st) == 0 && S_ISDIR(dir_st.st_mode)) {
      existing_dirs.push_back(dir);
    }
  }

  // At least one directory should exist
  EXPECT_GT(existing_dirs.size(), 0)
      << "At least one output directory should exist";

  // Count total flow files created
  int total_flow_files = 0;

  for (const auto &dir : existing_dirs) {
    std::string dir_path = output_dir + "/" + dir;
    int files_in_dir = count_files_in_directory(dir_path);
    total_flow_files += files_in_dir;

    // Validate each pcap file in this directory
    DIR *dir_ptr = opendir(dir_path.c_str());
    if (dir_ptr) {
      struct dirent *entry;
      while ((entry = readdir(dir_ptr)) != nullptr) {
        if (entry->d_type == DT_REG) {
          std::string file_path = dir_path + "/" + entry->d_name;
          EXPECT_TRUE(validate_pcap_file(file_path))
              << "Invalid pcap file: " << file_path;
        }
      }
      closedir(dir_ptr);
    }
  }

  // Validate flow count
  EXPECT_GT(total_flow_files, 0) << "Should create at least one flow file";
  LOG(INFO) << "Created " << total_flow_files << " flow files";

  // Validate specific flow types based on the sample file
  // The sample file should have TCP SYN flows
  std::string tcp_syn_dir = output_dir + "/tcp_syn";
  if (std::find(existing_dirs.begin(), existing_dirs.end(), "tcp_syn") !=
      existing_dirs.end()) {
    int tcp_syn_files = count_files_in_directory(tcp_syn_dir);
    EXPECT_GT(tcp_syn_files, 0) << "Should have TCP SYN flows";

    // Check that each flow file has a reasonable size
    DIR *tcp_syn_dir_ptr = opendir(tcp_syn_dir.c_str());
    if (tcp_syn_dir_ptr) {
      struct dirent *entry;
      while ((entry = readdir(tcp_syn_dir_ptr)) != nullptr) {
        if (entry->d_type == DT_REG) {
          std::string file_path = tcp_syn_dir + "/" + entry->d_name;
          struct stat file_st;
          if (stat(file_path.c_str(), &file_st) == 0) {
            EXPECT_GT(file_st.st_size, 100)
                << "Flow file should have reasonable size: " << file_path;
            EXPECT_LT(file_st.st_size, 100000)
                << "Flow file should not be unreasonably large: " << file_path;
          }
        }
      }
      closedir(tcp_syn_dir_ptr);
    }
  }
}

TEST_F(Pkt2FlowIntegrationTest, ValidateFlowFileNames) {
  // Test parameters
  std::string sample_file = "../sample/200722_win_scale_examples_anon.pcapng";
  std::string output_dir = test_output_dir;

  // Check if sample file exists
  struct stat st;
  if (stat(sample_file.c_str(), &st) != 0) {
    GTEST_SKIP() << "Sample pcap file not found: " << sample_file;
  }

  // Run pkt2flow
  std::string command = "./pkt2flow -u -o " + output_dir + " " + sample_file;
  int result = system(command.c_str());
  EXPECT_EQ(result, 0) << "pkt2flow should exit successfully";

  // Validate file naming convention
  std::vector<std::string> flow_dirs = {"tcp_syn", "tcp_nosyn", "udp",
                                        "others"};
  for (const auto &dir : flow_dirs) {
    std::string dir_path = output_dir + "/" + dir;
    DIR *dir_ptr = opendir(dir_path.c_str());
    if (dir_ptr) {
      struct dirent *entry;
      while ((entry = readdir(dir_ptr)) != nullptr) {
        if (entry->d_type == DT_REG) {
          std::string filename = entry->d_name;

          // Check file extension
          EXPECT_TRUE(filename.find(".pcap") != std::string::npos)
              << "Flow file should have .pcap extension: " << filename;

          // Check that filename contains IP addresses and ports
          EXPECT_TRUE(filename.find("_") != std::string::npos)
              << "Flow filename should contain underscores: " << filename;

          // Check that filename contains timestamp
          EXPECT_TRUE(filename.find("1595") != std::string::npos)
              << "Flow filename should contain timestamp: " << filename;
        }
      }
      closedir(dir_ptr);
    }
  }
}

TEST_F(Pkt2FlowIntegrationTest, ValidatePcapFileHeaders) {
  // Test parameters
  std::string sample_file = "../sample/200722_win_scale_examples_anon.pcapng";
  std::string output_dir = test_output_dir;

  // Check if sample file exists
  struct stat st;
  if (stat(sample_file.c_str(), &st) != 0) {
    GTEST_SKIP() << "Sample pcap file not found: " << sample_file;
  }

  // Run pkt2flow
  std::string command = "./pkt2flow -u -o " + output_dir + " " + sample_file;
  int result = system(command.c_str());
  EXPECT_EQ(result, 0) << "pkt2flow should exit successfully";

  // Validate pcap file headers using tcpdump
  std::vector<std::string> flow_dirs = {"tcp_syn", "tcp_nosyn", "udp",
                                        "others"};
  for (const auto &dir : flow_dirs) {
    std::string dir_path = output_dir + "/" + dir;
    DIR *dir_ptr = opendir(dir_path.c_str());
    if (dir_ptr) {
      struct dirent *entry;
      while ((entry = readdir(dir_ptr)) != nullptr) {
        if (entry->d_type == DT_REG) {
          std::string file_path = dir_path + "/" + entry->d_name;

          // Use tcpdump to validate pcap file format
          std::string tcpdump_cmd =
              "tcpdump -r " + file_path + " > /dev/null 2>&1";
          int tcpdump_result = system(tcpdump_cmd.c_str());
          EXPECT_EQ(tcpdump_result, 0)
              << "tcpdump should be able to read pcap file: " << file_path;
        }
      }
      closedir(dir_ptr);
    }
  }
}
