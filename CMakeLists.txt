cmake_minimum_required(VERSION 3.16)

project(pkt2flow
    VERSION 1.2.0
    DESCRIPTION "A simple utility to classify packets into flows"
    LANGUAGES C CXX)

# Set C and C++ standards
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable compile commands for better IDE support
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Set default build type to Release if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS_DEBUG "-g -O0")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")

# Platform-specific definitions
if(APPLE)
    add_definitions(-Ddarwin)
endif()

# Find required packages
find_package(PkgConfig REQUIRED)

# Find libpcap
pkg_check_modules(PCAP REQUIRED libpcap)
if(NOT PCAP_FOUND)
    find_library(PCAP_LIBRARIES pcap)
    if(NOT PCAP_LIBRARIES)
        message(FATAL_ERROR "libpcap not found")
    endif()
    set(PCAP_INCLUDE_DIRS "")
endif()

# Find glog
find_package(glog REQUIRED)

# Source files
set(PKT2FLOW_SOURCES
    pkt2flow.c
    flow_db.c
    utilities.c
)

# Create the main executable
add_executable(pkt2flow ${PKT2FLOW_SOURCES})

# Link libraries
target_link_libraries(pkt2flow 
    ${PCAP_LIBRARIES}
    glog::glog
)

# Include directories
target_include_directories(pkt2flow PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PCAP_INCLUDE_DIRS}
)

# Set compile definitions
target_compile_definitions(pkt2flow PRIVATE _GNU_SOURCE)

# Installation
include(GNUInstallDirs)
install(TARGETS pkt2flow 
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Enable testing
enable_testing()

# Build tests if requested
option(BUILD_TESTS "Build unit tests" ON)
if(BUILD_TESTS)
    # Find GoogleTest
    find_package(GTest REQUIRED)
    
    # Test source files
    set(TEST_SOURCES
        tests/test_flow_db.cpp
        tests/test_utilities.cpp
        tests/test_main.cpp
    )
    
    # Create test executable
    add_executable(pkt2flow_tests ${TEST_SOURCES})
    
    # Link test libraries
    target_link_libraries(pkt2flow_tests
        ${PCAP_LIBRARIES}
        glog::glog
        GTest::gtest
        GTest::gtest_main
    )
    
    # Include directories for tests
    target_include_directories(pkt2flow_tests PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${PCAP_INCLUDE_DIRS}
    )
    
    # Set compile definitions for tests
    target_compile_definitions(pkt2flow_tests PRIVATE _GNU_SOURCE)
    
    # Add test
    add_test(NAME pkt2flow_unit_tests COMMAND pkt2flow_tests)
    
    # Create a library from the source files for testing
    add_library(pkt2flow_lib STATIC
        flow_db.c
        utilities.c
    )
    
    target_include_directories(pkt2flow_lib PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${PCAP_INCLUDE_DIRS}
    )
    
    target_link_libraries(pkt2flow_lib 
        ${PCAP_LIBRARIES}
        glog::glog
    )
    
    target_compile_definitions(pkt2flow_lib PRIVATE _GNU_SOURCE)
    
    # Link the library to tests
    target_link_libraries(pkt2flow_tests pkt2flow_lib)
endif()

# CPack configuration for packaging
include(CPack)
set(CPACK_PACKAGE_NAME "pkt2flow")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_VENDOR "chenxm")
set(CPACK_PACKAGE_CONTACT "chenxm35@gmail.com")