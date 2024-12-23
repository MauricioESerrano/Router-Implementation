# pa2a-starter

## Info

Name: Mauricio Serrano

## Description and Overview

- sr_arpcache.c - 

table_lookup
Looks up the routing table to find the next hop IP and outgoing interface for a given destination IP.

icmp_hostUnreachable
Creates and sends an ICMP "Host Unreachable" message for a given packet when the destination is unreachable. It queues the packet in the ARP cache if the next hop's MAC address is unknown.

arp_SendRequest
Constructs and sends an ARP request to resolve the MAC address for a given IP address.

handle_arpreq
Handles ARP requests by:

Resending ARP requests if retries are below the threshold.
Sending ICMP "Host Unreachable" messages for packets queued for the unresolved ARP request if retries exceed the limit.

sr_arpcache_sweepreqs
Iterates through all ARP requests in the cache and processes them using handle_arpreq

- sr_router.c - 

bool_tipInInterface
This function checks whether a given IP address matches any of the IP addresses assigned to the router's interfaces. It takes the router instance (sr) and the IP address (ip) as inputs. The function iterates through the list of interfaces associated with the router. If an interface's IP matches the given IP, it returns 1 (indicating a match); otherwise, it continues searching until the end of the list. If no match is found, the function returns 0. This utility is essential for determining if a packet is destined for one of the router’s interfaces.

find_nextHop
This function looks up the routing table to find the appropriate next-hop entry for a given destination IP address. It takes the router instance (sr) and the destination IP address (ip_dst) as inputs. The function iterates through the routing table entries and compares each entry's destination address with the given IP. If a match is found, it returns the corresponding routing table entry. If no match is found, the function returns NULL, indicating that the destination IP is unreachable. This function plays a crucial role in forwarding decisions within the router.

arp_sendReply
This function handles the generation and transmission of an ARP reply in response to an ARP request. It takes the router instance (sr), the received ARP request packet (packet), and the receiving interface name (interface) as inputs. The function extracts the ARP and Ethernet headers from the request packet and checks if the target IP address in the ARP request matches the IP address of the receiving interface. If there is a match, it constructs an ARP reply packet, including the MAC address and IP address of the responding interface. The ARP reply is then sent back to the requester using sr_send_packet. This function ensures proper ARP resolution by responding to valid requests.

arp_handleReply
This function processes incoming ARP replies and resolves any pending requests for the corresponding IP address. It takes the router instance (sr) and the ARP reply header (arp_reply_hdr) as inputs. The function extracts the sender's IP address from the ARP reply and searches the ARP request queue for a matching request. If a matching request is found, it iterates through the queued packets associated with the request, updates the Ethernet headers with the sender's MAC address, and sends the packets using sr_send_packet. After processing all packets, the function removes the request from the ARP request queue. This function ensures the router can successfully transmit packets to a previously unresolved destination.

icmp_echoReply
This function generates an ICMP echo reply in response to an ICMP echo request. It takes the router instance (sr), the received packet (packet), the packet's length (len), and the receiving interface name (interface) as inputs. The function allocates memory for a new packet, swaps the source and destination fields in the Ethernet and IP headers, and sets the ICMP type to 0 (echo reply). It recalculates checksums for both the IP and ICMP headers to ensure integrity. If the destination IP requires ARP resolution, the function queues the packet for resolution. Otherwise, it can send the reply directly. This function allows the router to properly respond to ping requests.

icmp_ttlError
This function constructs and sends an ICMP Time-to-Live (TTL) exceeded or destination unreachable error message when the TTL of a packet reaches zero or the destination is unreachable. It takes the router instance (sr), the received packet (packet), the receiving interface name (interface), and the ICMP type and code (type and code) as inputs. The function allocates memory for a new ICMP error message, constructs the Ethernet, IP, and ICMP headers, and copies the original packet's IP header and the first 8 bytes of its payload into the ICMP message. After recalculating the checksums, the function queues the packet for ARP resolution or sends it directly if the ARP entry is available. This function helps the router notify senders about packet delivery issues.

sr_handlepacket
This is the main packet processing function, called whenever the router receives a packet. It takes the router instance (sr), the received packet (packet), its length (len), and the receiving interface name (interface) as inputs. The function first verifies the packet's integrity and determines its type by examining the Ethernet header. If the packet is an ARP request or reply, it invokes arp_sendReply or arp_handleReply, respectively. For IP packets, it validates the IP checksum and handles packets destined for the router (e.g., by responding to ICMP echo requests with icmp_echoReply) or forwards them to the next hop if the TTL is valid. If no route is found or the TTL has expired, it generates an ICMP error using icmp_ttlError. This function orchestrates all packet-handling logic in the router.






