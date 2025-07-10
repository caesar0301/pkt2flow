#include <gtest/gtest.h>
#include <glog/logging.h>

int main(int argc, char **argv) {
    // Initialize Google Logging
    google::InitGoogleLogging(argv[0]);
    
    // Initialize Google Test
    ::testing::InitGoogleTest(&argc, argv);
    
    // Run all tests
    int result = RUN_ALL_TESTS();
    
    // Cleanup Google Logging
    google::ShutdownGoogleLogging();
    
    return result;
}