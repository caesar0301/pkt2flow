# Enhanced Protocol Support in pkt2flow

This document describes the enhanced protocol and link type support that has been added to pkt2flow to handle a wider variety of network capture formats and protocols.

## Overview

The original pkt2flow tool was designed to handle Ethernet-based captures with TCP and UDP protocols. The enhanced version now supports additional link types and transport protocols commonly found in real-world network analysis scenarios.

## Supported Link Types

### Previously Supported
- **DLT_EN10MB** - Ethernet (10Mb)
- **DLT_IEEE802** - Token Ring
- **DLT_ARCNET** - ARCNET
- **DLT_SLIP** - Serial Line IP
- **DLT_PPP** - Point-to-point Protocol
- **DLT_FDDI** - FDDI
- **DLT_ATM_RFC1483** - LLC-encapsulated ATM

### Newly Added (High Priority)
- **DLT_RAW** - Raw IP packets (both IPv4 and IPv6)
- **DLT_LINUX_SLL** - Linux cooked capture (SLL)
- **DLT_IPV4** - Raw IPv4 packets only
- **DLT_IPV6** - Raw IPv6 packets only

### Why These Matter
- **DLT_RAW**: Common in VPN captures, certain network monitoring tools, and raw packet captures
- **DLT_LINUX_SLL**: Very common when using `tcpdump -i any` on Linux systems
- **DLT_IPV4/DLT_IPV6**: More specific raw IP handling for IPv4-only or IPv6-only captures

## Supported Transport Protocols

### Previously Supported
- **IPPROTO_TCP** (6) - Transmission Control Protocol
- **IPPROTO_UDP** (17) - User Datagram Protocol

### Newly Added (High Priority)
- **IPPROTO_SCTP** (132) - Stream Control Transmission Protocol
- **IPPROTO_DCCP** (33) - Datagram Congestion Control Protocol

### Better Categorized
- **IPPROTO_ICMP** (1) - Internet Control Message Protocol
- **IPPROTO_ICMPV6** (58) - ICMP for IPv6

### Other Protocols
- **UDP-Lite** (136) - Handled as "other" protocol
- All other IP protocols are handled as "other" protocols

## Implementation Details

### Link Type Detection
The tool now automatically detects the link type of the input pcap file using `pcap_datalink()` and routes packets to the appropriate handler:

```c
switch (link_type) {
case DLT_EN10MB:      /* Ethernet */
case DLT_IEEE802:     /* Token Ring */
case DLT_ARCNET:      /* ARCNET */
case DLT_SLIP:        /* SLIP */
case DLT_PPP:         /* PPP */
case DLT_FDDI:        /* FDDI */
case DLT_ATM_RFC1483: /* ATM RFC1483 */
  syn_detected = pcap_handle_ethernet(&af_6tuple, hdr, pkt);
  break;
case DLT_RAW:         /* Raw IP */
  syn_detected = pcap_handle_raw_ip(&af_6tuple, hdr, pkt);
  break;
case DLT_LINUX_SLL:   /* Linux cooked capture */
  syn_detected = pcap_handle_linux_sll(&af_6tuple, hdr, pkt);
  break;
case DLT_IPV4:        /* Raw IPv4 */
case DLT_IPV6:        /* Raw IPv6 */
  syn_detected = pcap_handle_raw_ip(&af_6tuple, hdr, pkt);
  break;
default:
  fprintf(stderr, "Unsupported link type: %d\n", link_type);
  return;
}
```

### Protocol Handling
Enhanced protocol support in the layer 4 handler:

```c
switch (proto) {
case IPPROTO_UDP:
  // Handle UDP packets
  break;
case IPPROTO_TCP:
  // Handle TCP packets
  break;
case IPPROTO_SCTP:
  // Handle SCTP packets
  break;
case IPPROTO_DCCP:
  // Handle DCCP packets
  break;
default:
  // Handle other protocols
  break;
}
```

## Usage Examples

### Processing Raw IP Captures
```bash
# Process a raw IP capture (like VPN captures)
./pkt2flow -u -v -x vpn_capture.pcap
```

### Processing Linux SLL Captures
```bash
# Process a Linux cooked capture
./pkt2flow -u -v -x linux_capture.pcap
```

### Processing with All Protocols
```bash
# Process with all protocol types enabled
./pkt2flow -u -v -x -o output_dir input.pcap
```

## Testing

Use the provided test script to validate protocol support:

```bash
./scripts/test_protocol_support.sh
```

This script tests:
- Raw IP support
- UDP-Lite handling
- Standard TCP/UDP processing
- Link type detection

## Common Use Cases

### 1. VPN Traffic Analysis
Raw IP captures are common in VPN environments where the capture is taken at the IP level rather than the Ethernet level.

### 2. Linux Network Monitoring
Linux SLL captures are generated when using `tcpdump -i any` or similar commands that capture from all interfaces.

### 3. Telecom and Signaling
SCTP is commonly used in telecom applications for signaling protocols like SIGTRAN.

### 4. Modern Transport Protocols
DCCP is used in some modern applications that need reliable but unordered delivery.

## Troubleshooting

### Unsupported Link Type Error
If you see "Unsupported link type: X", the capture uses a link type not yet supported. Common unsupported types include:
- **DLT_IEEE802_11** (105) - 802.11 wireless frames
- **DLT_USB** (186) - USB packets
- **DLT_BLUETOOTH_HCI_H4** (187) - Bluetooth packets

### Protocol Not Extracted
If a protocol is not being extracted, check:
1. The `-x` flag is used to enable "other" protocols
2. The protocol is actually present in the capture
3. The protocol is supported by the tool

## Future Enhancements

### Medium Priority Additions
- **DLT_IEEE802_11** - 802.11 wireless frame support
- **DLT_USB** - USB packet analysis
- **DLT_BLUETOOTH_HCI_H4** - Bluetooth packet analysis

### Low Priority Additions
- More exotic link types for specialized analysis
- Additional transport protocols as needed

## Compatibility

The enhanced protocol support is fully backward compatible. All existing functionality continues to work as before, with the addition of new capabilities.

## Contributing

When adding support for new protocols or link types:

1. Add the link type to the switch statement in `packet_handler()`
2. Create a handler function if needed
3. Add protocol support to `pcap_handle_layer4()` if it's a transport protocol
4. Update the protocol filtering logic
5. Add appropriate tests
6. Update this documentation

## References

- [libpcap DLT values](https://www.tcpdump.org/linktypes.html)
- [IP Protocol Numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
- [SCTP RFC 4960](https://tools.ietf.org/html/rfc4960)
- [DCCP RFC 4340](https://tools.ietf.org/html/rfc4340)
