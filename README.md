# Network Latency Measurement with Python

## Overview
This script is intended to be run with a capture file (libpcap) that contins both ingress and egress traffic through a 
network device. The script will attempt to match each ingress request with its corresponding egress request to calculate
the unidirectional latency introduced by the device being measured.

## Limitations
* Only compatible with clear-text HTTP sessions; TLS communication is not supported.
* Only one session at a time is supported
  * The request-matching logic is absolutely trivial at this time and not capable of differentiating between multiple 
    simultaneous sessions.
  * For higher concurrency scenarios use pcap filters to restrict the recorded traffic to a single client session.
* Packet header offsets are currently hard-coded rather than dynamically calculated as the headers are processed


## Future Enhancements (TODO)
* Update header field offset calculation to be dynamic rather than static
* Support for multiple concurrent sessions
* Support for UDP latency 
* Support for restricting measurment to specific requests using regex matching
