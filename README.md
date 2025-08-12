# pkt2flow

[![Build Status](https://github.com/caesar0301/pkt2flow/actions/workflows/ci.yml/badge.svg)](https://github.com/caesar0301/pkt2flow/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS-blue)]()

A simple, cross-platform utility to classify packets into flows using only the essential 4-tuple (src_ip, dst_ip, src_port, dst_port). Each flow is saved as a separate pcap file, named with its 4-tuple and the timestamp of its first packet. No payload reassembly or extra processing is performed—just pure flow separation for your analysis needs.

## Why pkt2flow?

Existing tools like `tcpflow`, `tcpslice`, and `tcpsplit` either reduce trace volume or reassemble payloads, which may not fit all research or analysis needs. `pkt2flow` fills the gap by simply splitting packets into flows, making it ideal for deep packet inspection, flow classification, and traffic research.

## Installation & Build

### Prerequisites

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y libpcap-dev libgoogle-glog-dev libgtest-dev cmake build-essential
```

**macOS (Intel/Apple Silicon):**
```bash
brew install libpcap glog googletest cmake
```
> **Note for Apple Silicon (M1/M2):**
> If you encounter issues with `libpcap` not being found, set:
> ```bash
> export PKG_CONFIG_PATH="/opt/homebrew/opt/libpcap/lib/pkgconfig"
> ```

### Build Steps

1. Clone the repository:
    ```bash
    git clone https://github.com/caesar0301/pkt2flow.git
    cd pkt2flow
    ```
2. Configure and build:
    ```bash
    mkdir build && cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make
    ```
3. (Optional) Run tests:
    ```bash
    ctest --verbose
    ```
4. (Optional) Install:
    ```bash
    sudo make install
    ```

#### Build Options
- `BUILD_TESTS`: Enable/disable unit tests (default: ON)
- `CMAKE_BUILD_TYPE`: Set build type (Debug, Release, etc.)

Example:
```bash
cmake .. -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=OFF
```

## Usage

```bash
./pkt2flow [-huvx] [-o outdir] pcapfile

Options:
  -h    Print this help and exit
  -u    Also dump (U)DP flows
  -v    Also dump in(v)alid TCP flows without the SYN option
  -x    Also dump non-UDP/non-TCP IP flows
  -o    (O)utput directory
```

### Example

```bash
./pkt2flow -u -o output_flows/ input.pcap
```
This will split all TCP and UDP flows from `input.pcap` into separate files in the `output_flows/` directory.

## Development

### Running Tests
```bash
cd build && ctest
# Or run a specific test:
./pkt2flow_tests --gtest_filter="FlowDbTest.*"
```

### Code Quality
```bash
cppcheck --enable=all *.c *.h
clang-format --dry-run *.c *.h
```

## Troubleshooting

- **libpcap not found on macOS (Apple Silicon):**
  Set the PKG_CONFIG_PATH before running cmake:
  ```bash
  export PKG_CONFIG_PATH="/opt/homebrew/opt/libpcap/lib/pkgconfig"
  ```

- **Linker warnings about /usr/local/opt/llvm/lib:**
  These are harmless if you are not using a custom LLVM install. You can ignore them or remove the path from your environment.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with appropriate tests
4. Ensure all tests pass and code follows the style guide
5. Submit a pull request

## Contributors

[![Contributors](https://contrib.rocks/image?repo=caesar0301/pkt2flow "pkt2flow contributors")](https://github.com/caesar0301/pkt2flow/graphs/contributors)

