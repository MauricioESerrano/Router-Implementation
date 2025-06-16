# Software Router Implementation

## Overview

This project implements a simple software router that operates at the Ethernet layer. It handles packet forwarding using ARP, IP, and ICMP protocols and supports static routing through a user-defined routing table. The router processes raw Ethernet frames, enabling packet forwarding between clients and application servers in both single-router and multi-router topologies.

Developed in C and tested within a Dockerized Mininet environment, the router is capable of routing real packets, responding to ARP and ICMP messages, and ensuring reliable delivery through ARP request retry and packet queuing mechanisms.

## Features

### Project
- Exact-match routing table for packet forwarding
- Sends ARP requests for unknown MAC addresses
- Replies to ARP requests directed at the router
- Responds to ICMP Echo Requests with Echo Replies
- Generates ICMP errors: Destination Net Unreachable, Host Unreachable, and Time Exceeded
- Queues packets while waiting for ARP resolution
- Retries ARP requests up to 5 times before sending ICMP Host Unreachable
- Longest Prefix Match routing logic
- ARP caching with 15-second timeout
- Handles ICMP Port Unreachable for TCP/UDP packets to router interfaces
- Supports full multi-router topologies with 4 interconnected routers
- Compatible with traceroute and HTTP clients

## Key Functions

- `sr_handlepacket(...)`: Main dispatcher for all received Ethernet frames
- `sr_send_packet(...)`: Sends a raw packet out a specified interface
- `sr_arpcache_sweepreqs(...)`: Resends ARP requests and handles timeouts
- `handle_ip(...)`: Verifies IP headers, decrements TTL, and forwards packets
- `handle_arp(...)`: Processes ARP requests and replies
- `send_icmp(...)`: Constructs and sends ICMP messages (echo replies and errors)
- `longest_prefix_match(...)`: Selects routing entry based on prefix length

## Development Environment

- Docker-based container setup with Mininet and POX
- VSCode Dev Container integration with tasks.json automation
- Logging support via `-l` flag to capture `.pcap` files for Wireshark/tcpdump
- Manual and automated testing (including Python unittest + Scapy tests)



## Client ↔ Router(s) ↔ Server(s)

- Client: `10.0.1.100`
- Servers: `192.168.2.2`, `192.168.3.2`
- Routers: `sw1`, `sw2`, `sw3`, `sw4`, each with multiple interfaces

## Sample Output

### ✅ Ping

```sh
mininet> client ping -c 3 192.168.2.2
PING 192.168.2.2 (192.168.2.2) 56 data bytes
64 bytes from 192.168.2.2: icmp_seq=1 ttl=64 time=0.502 ms
64 bytes from 192.168.2.2: icmp_seq=2 ttl=64 time=0.374 ms
64 bytes from 192.168.2.2: icmp_seq=3 ttl=64 time=0.361 ms
```


### 📍 Traceroute
```sh
mininet> client traceroute 192.168.2.2
traceroute to 192.168.2.2 (192.168.2.2), 64 hops max
  1   192.168.1.1  34.877ms  5.149ms  2.269ms 
  2   192.168.0.1  16.613ms  6.963ms  6.551ms 
  3   192.168.0.6  9.726ms  10.019ms  9.958ms 
  4   192.168.2.2  11.679ms  11.859ms  11.896ms 
```


### 🌐 HTTP Download


```
mininet> client wget -O- http://192.168.2.2
--2024-11-26 03:19:28--  http://192.168.2.2/
Connecting to 192.168.2.2:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 161 [text/html]
Saving to: 'STDOUT'
```

Testing
Manual testing through the Mininet CLI (ping, traceroute, wget)

Packet capture logging via:
```
./sr -l test1.pcap -v sw1 -r rtable1
```

- Automated testing using Python’s unittest and Scapy-based packet assertions

- Included support for tests/test_example.py, test_sample.py, and more

# Conclusion

This router simulates the behavior of real-world IP routers using static routing tables, ARP resolution, ICMP messaging, and packet queuing. The implementation supports both simple and multi-router topologies, making it ideal for understanding the fundamentals of Layer 2/3 packet forwarding. With ARP caching and longest-prefix routing, it extends beyond a basic forwarding engine and serves as a solid base for further experimentation with dynamic routing protocols or NAT features.




