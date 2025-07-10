pkt2flow
========

by chenxm, Shanghai Jiao Tong Univ.
chenxm35@gmail.com

2012-2024

**©MIT LICENSED**

A simple utility to classify packets into flows. It's so simple that only one task
is aimed to finish.

For Deep Packet Inspection or flow classification, it's so common to analyze the
feature of one specific flow. I have make the attempt to use made-ready tools like
`tcpflows`, `tcpslice`, `tcpsplit`, but all these tools try to either decrease the
trace volume (under requirement) or resemble the packets into flow payloads (over
requirement). I have not found a simple tool to classify the packets into flows without
further processing. This is why this program is born.

The inner function of this program behaves using the 4-tuple (src_ip, dst_ip, src_port, dst_port)
to seperate the packets into TCP or UDP flows. Each flow will be saved into a pcap 
file named with 4-tuple and the timestamp of the first packet of the flow. The packets are 
saved in the order as read from the source. Any further processing like TCP resembling is
not performed. The flow timeout is considered as 30 minutes which can be changed in pkt2flow.h.

## Features

- **Cross-platform**: Supports both Linux and macOS
- **Modern build system**: Uses CMake instead of SCons
- **Structured logging**: Integrated with Google glog for better debugging
- **Unit testing**: Comprehensive test suite using Google Test
- **CI/CD**: Automated testing with GitHub Actions
- **Static analysis**: Code quality checks with cppcheck

How to compile
----------

This program now uses CMake as the build system. You can follow these steps to compile:

### Prerequisites

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y \
    libpcap-dev \
    libgoogle-glog-dev \
    libgtest-dev \
    cmake \
    build-essential
```

**macOS:**
```bash
brew install \
    libpcap \
    glog \
    googletest \
    cmake
```

### Building

1. Clone the repository:
```bash
git clone https://github.com/caesar0301/pkt2flow.git
cd pkt2flow
```

2. Configure and build:
```bash
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

3. Run tests (optional):
```bash
ctest --verbose
```

4. Install (optional):
```bash
sudo make install
```

### Build Options

- `BUILD_TESTS`: Enable/disable unit tests (default: ON)
- `CMAKE_BUILD_TYPE`: Set build type (Debug, Release, RelWithDebInfo, MinSizeRel)

Example:
```bash
cmake .. -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=OFF
```

## Logging

The application now uses Google glog for structured logging. Logs are written to:
- Console (stderr) for important messages
- Log files in `./logs/` directory for detailed debugging

You can control logging verbosity with environment variables:
```bash
export GLOG_v=2  # Increase verbosity
export GLOG_log_dir=/custom/log/path
./pkt2flow input.pcap
```

Usage
--------
```bash
Usage: ./pkt2flow [-huvx] [-o outdir] pcapfile

	Options:
		-h	print this help and exit
		-u	also dump (U)DP flows
		-v	also dump the in(v)alid TCP flows without the SYN option
		-x	also dump non-UDP/non-TCP IP flows
		-o	(o)utput directory
```

## Development

### Running Tests

```bash
# Run all tests
cd build && ctest

# Run specific test
./build/pkt2flow_tests --gtest_filter="FlowDbTest.*"
```

### Code Quality

The project includes static analysis tools:

```bash
# Run cppcheck
cppcheck --enable=all *.c *.h

# Check formatting
clang-format --dry-run *.c *.h
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with appropriate tests
4. Ensure all tests pass and code follows the style guide
5. Submit a pull request

Contributors
--------

[![Contributors](https://contrib.rocks/image?repo=caesar0301/pkt2flow "pkt2flow contributors")](https://github.com/caesar0301/pkt2flow/graphs/contributors)

