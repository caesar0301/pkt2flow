#include <algorithm>
#include <dirent.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include <pcap/pcap.h>
#include <sys/stat.h>
#include <unistd.h>

extern "C" {
#include "pkt2flow.h"
}

// Global variables that would normally be set by main()
extern pcap_t *inputp;

class Pkt2FlowBaseTest : public ::testing::Test {
protected:
  void SetUp() override {
    // Initialize test output directory
    test_output_dir = "test_pkt2flow_out";
    mkdir(test_output_dir.c_str(), 0755);

    // Set global variables
    set_outputdir(test_output_dir.c_str());
    inputp = nullptr;

    // Initialize hash table
    init_hash_table();
  }

  void TearDown() override {
    // Clean up hash table
    free_hash_table();

    // Clean up test output directory
    cleanup_directory(test_output_dir);
    rmdir(test_output_dir.c_str());
  }

  std::string test_output_dir;

  // Process a pcap file using the pkt2flow library directly
  bool process_pcap_file(const std::string &pcap_file, uint32_t flags) {
    // Set the input file and dump flags using the new API
    set_readfile(pcap_file.c_str());
    set_dump_allowed(flags);

    // Open the trace file using the library function
    open_trace_file();

    // Process the trace using the library function
    process_trace();

    // Close the trace files using the library function
    close_trace_files();

    return true;
  }

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

  // Helper function to count total packets in a pcap file
  int count_packets_in_pcap(const std::string &file_path) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(file_path.c_str(), errbuf);
    if (!pcap) {
      return 0;
    }

    struct pcap_pkthdr header;
    const u_char *packet;
    int packet_count = 0;

    while ((packet = pcap_next(pcap, &header)) != nullptr) {
      packet_count++;
    }

    pcap_close(pcap);
    return packet_count;
  }

  // Validate flow files in a specific directory
  void validate_flow_directory(const std::string &dir_path,
                               const std::string &protocol_name) {
    struct stat dir_st;
    if (stat(dir_path.c_str(), &dir_st) != 0) {
      // Directory doesn't exist, which might be expected for some protocols
      return;
    }

    EXPECT_TRUE(S_ISDIR(dir_st.st_mode))
        << protocol_name << " directory should be a directory: " << dir_path;

    int files_in_dir = count_files_in_directory(dir_path);
    if (files_in_dir > 0) {
      LOG(INFO) << "Found " << files_in_dir << " " << protocol_name
                << " flow files";

      // Validate each pcap file in this directory
      DIR *dir_ptr = opendir(dir_path.c_str());
      if (dir_ptr) {
        struct dirent *entry;
        while ((entry = readdir(dir_ptr)) != nullptr) {
          if (entry->d_type == DT_REG) {
            std::string file_path = dir_path + "/" + entry->d_name;
            EXPECT_TRUE(validate_pcap_file(file_path))
                << "Invalid " << protocol_name << " pcap file: " << file_path;

            // Check file size
            struct stat file_st;
            if (stat(file_path.c_str(), &file_st) == 0) {
              EXPECT_GT(file_st.st_size, 100)
                  << protocol_name
                  << " flow file should have reasonable size: " << file_path;
              EXPECT_LT(file_st.st_size, 1000000)
                  << protocol_name
                  << " flow file should not be unreasonably large: "
                  << file_path;
            }

            // Validate filename contains expected patterns
            std::string filename = entry->d_name;
            EXPECT_TRUE(filename.find(".pcap") != std::string::npos)
                << protocol_name
                << " flow file should have .pcap extension: " << filename;
          }
        }
        closedir(dir_ptr);
      }
    }
  }

  // Get total flow count across all directories
  int get_total_flow_count() {
    std::vector<std::string> flow_dirs = {"tcp_syn", "tcp_nosyn", "udp",
                                          "others"};
    int total_flows = 0;

    for (const auto &dir : flow_dirs) {
      std::string dir_path = test_output_dir + "/" + dir;
      total_flows += count_files_in_directory(dir_path);
    }

    return total_flows;
  }
};
