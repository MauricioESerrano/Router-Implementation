/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

int bool_tipInInterface(struct sr_instance* sr, uint32_t ip) {
  struct sr_if* iface = sr->if_list;
  while (iface != NULL) {
    if (iface->ip == ip) {
      return 1;
    }
    iface = iface->next;
  }
  return 0;
}

struct sr_rt *find_nextHop(struct sr_instance *sr, uint32_t ip_dst) {

  struct sr_rt *entry = sr->routing_table;
  
  while (entry != NULL) {
    if (entry->dest.s_addr == ip_dst) {
      return entry;
    }
    entry = entry->next;
  }
  return NULL;
}

void arp_sendReply(struct sr_instance* sr, uint8_t *packet, char* interface) {

  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  struct sr_if* iface = sr_get_interface(sr, interface);

  if (arp_hdr->ar_tip == iface->ip) {

    unsigned int repLen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *repPkt = (uint8_t *)malloc(repLen);

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)repPkt;
    memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_arp);

    sr_arp_hdr_t *rply_arp_hdr = (sr_arp_hdr_t *)(repPkt + sizeof(sr_ethernet_hdr_t));
    rply_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    rply_arp_hdr->ar_pro = htons(ethertype_ip);
    rply_arp_hdr->ar_hln = ETHER_ADDR_LEN;
    rply_arp_hdr->ar_pln = sizeof(uint32_t);
    rply_arp_hdr->ar_op = htons(arp_op_reply);
    memcpy(rply_arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
    rply_arp_hdr->ar_sip = iface->ip;
    memcpy(rply_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    rply_arp_hdr->ar_tip = arp_hdr->ar_sip;

    sr_send_packet(sr, repPkt, repLen, interface);
  } 
  else {
    printf("target ip no match\n");
  }
}

void arp_handleReply(struct sr_instance* sr, struct sr_arp_hdr* arp_reply_hdr) {

  uint32_t reply_sender_ip = arp_reply_hdr->ar_sip;
  struct sr_arpreq* targ_arpreq = NULL;

  struct sr_arpreq* curr_arpreq = sr->cache.requests;
  
  while (curr_arpreq != NULL) {
    if (curr_arpreq->ip == reply_sender_ip) {
      targ_arpreq = curr_arpreq;
    }
    curr_arpreq = curr_arpreq->next;
  }

  if (targ_arpreq == NULL) {
    return;
  }

  struct sr_packet* curr_packet = targ_arpreq->packets;
  while (curr_packet !=  NULL) {
    struct sr_ethernet_hdr* curr_eth_head = (struct sr_ethernet_hdr *) curr_packet->buf;
    memcpy(curr_eth_head->ether_dhost, arp_reply_hdr->ar_sha, ETHER_ADDR_LEN);
    sr_send_packet(sr, curr_packet->buf, curr_packet->len, curr_packet->iface);

    curr_packet = curr_packet->next;
  }

  sr_arpreq_destroy(&sr->cache, targ_arpreq);
}

void icmp_echoReply(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* interface) {

  uint8_t* buf = malloc(len);
  if (!buf) {
    fprintf(stderr, " buf not allocated properly \n");
    return;
  }

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t08_hdr_t *icmp_hdr = (sr_icmp_t08_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  struct sr_rt* entry = find_nextHop(sr, ip_hdr->ip_src);
  if (entry == NULL) return;
  struct sr_if* existing_interface = sr_get_interface(sr, entry->interface);

  sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)buf;
  sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t08_hdr_t *new_icmp_hdr = (sr_icmp_t08_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(new_eth_hdr->ether_shost, existing_interface->addr, ETHER_ADDR_LEN);
  new_eth_hdr->ether_type = eth_hdr->ether_type;

  memcpy(new_ip_hdr, ip_hdr, sizeof(sr_ip_hdr_t));
  new_ip_hdr->ip_src = existing_interface->ip;
  new_ip_hdr->ip_dst = ip_hdr->ip_src;
 
  new_ip_hdr->ip_ttl = 64;
  new_ip_hdr->ip_sum = 0; 
  new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

  memcpy(new_icmp_hdr, icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
  new_icmp_hdr->icmp_type = 0;
  new_icmp_hdr->icmp_code = 0;
  new_icmp_hdr->icmp_sum = 0;
  new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, (len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t)));

  struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, entry->gw.s_addr, buf, len, entry->interface);
  handle_arpreq(req, &sr->cache, sr);
}

void icmp_ttlError(struct sr_instance *sr, uint8_t* packet, char* interface, int type, int code) {
    
  unsigned int len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t11_hdr);
  
  uint8_t* buf = malloc(len);
  
  if (!buf) {
    fprintf(stderr, " buf not allocated right \n");
    return;
  }

  struct sr_if* received_if = sr_get_interface(sr, interface);
  struct sr_ethernet_hdr* packet_eth_head = (struct sr_ethernet_hdr *) packet;
  struct sr_ip_hdr* packet_ip_head = (struct sr_ip_hdr *) (packet + sizeof(struct sr_ethernet_hdr));

  struct sr_ethernet_hdr* ether_hdr = (struct sr_ethernet_hdr *) buf;
  memcpy(ether_hdr->ether_dhost, packet_eth_head->ether_shost, ETHER_ADDR_LEN);
  memcpy(ether_hdr->ether_shost, packet_eth_head->ether_dhost, ETHER_ADDR_LEN);
  ether_hdr->ether_type = htons(ethertype_ip);

  struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr *) (buf + sizeof(struct sr_ethernet_hdr));
  ip_hdr->ip_hl = 5;
  ip_hdr->ip_v = 4;
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_len = htons(20 + sizeof(struct sr_icmp_t11_hdr));
  ip_hdr->ip_id = 0;
  ip_hdr->ip_off = 0;
  ip_hdr->ip_ttl = INIT_TTL;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->ip_dst = packet_ip_head->ip_src;

  struct sr_rt* rt_entry = find_nextHop(sr, packet_ip_head->ip_src);
  if (rt_entry == NULL) {
    fprintf(stderr, "routing not found\n");
    free(buf);
    return;
  }

  struct sr_if* exiting_if = sr_get_interface(sr, rt_entry->interface);

  if (!exiting_if) {
    fprintf(stderr, "interface not found\n");
    free(buf);
    return;
  }

  ip_hdr->ip_src = exiting_if->ip;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));

  struct sr_icmp_t11_hdr* icmp_hdr = (struct sr_icmp_t11_hdr *) (buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  memcpy(icmp_hdr->data, packet_ip_head, ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(struct sr_icmp_t11_hdr));

  struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, packet_ip_head->ip_src, buf, len, exiting_if);
  handle_arpreq(req, &sr->cache, sr);

  // sr_send_packet(sr, buf, len, exiting_if->name);
  // free(buf);
}


/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

// todo lengths have been altered, if not working. possible problem beacuse of that
void sr_handlepacket(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* interface/* lent */) {
  
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  printf("-------------------------INCOMING PACKET---------------------------\n");
  print_hdrs(packet,len);

  // -----------------------------------------------------------------------------------

  struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr*) packet;

  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    printf("Dropping packet: wrong ETH length. \n");
    return;
  }

  struct sr_if* recievering_interface = sr_get_interface(sr, interface);
  uint16_t eth_type = ethertype(eth_hdr);

  if (eth_type == ethertype_arp) {

    if (len - sizeof(struct sr_ethernet_hdr) < sizeof(struct sr_arp_hdr)) {
      fprintf(stderr, "Incoming ARP - Incorrect Length : Dropped \n");
      return;
    }

    struct sr_arp_hdr* arp_hdr = (struct sr_arp_hdr*) (packet + sizeof(struct sr_ethernet_hdr));

    if (arp_hdr->ar_tip == recievering_interface->ip) {
      if (ntohs(arp_hdr->ar_op) == arp_op_request) {
        fprintf(stderr, "Sending ARP Reply \n");
        arp_sendReply(sr, packet, recievering_interface);
      }
      else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
        fprintf(stderr, "Handling ARP reply\n");
        arp_handleReply(sr, arp_hdr);
      }
      else {
        fprintf(stderr, "Did not match recieving Interface's IP \n");
      }
    }
  }
  
  else if (eth_type == ethertype_ip) {

    if (len - sizeof(struct sr_ethernet_hdr) < sizeof(struct sr_ip_hdr)) {
      fprintf(stderr, "Incoming IP Packet - Incorrect Length : Dropped \n");
      return;
    }

    struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr*) (packet + sizeof(struct sr_ethernet_hdr));

    uint16_t tempIpCkSum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0; 
    uint16_t ipCheckSum = cksum(ip_hdr, ip_hdr->ip_hl*4);

    if(ipCheckSum != tempIpCkSum){
      fprintf(stderr, "Error - IN : IP Checksum failed\n");
      return;
    }

    if (bool_tipInInterface(sr, ip_hdr->ip_dst) == 0) {

      if (ip_hdr->ip_ttl == 1) {
        icmp_ttlError(sr, packet, interface, 11, 0);
        return;
      }

      struct sr_rt* entry = find_nextHop(sr, ip_hdr->ip_dst);

      if (entry == NULL) {
        icmp_ttlError(sr, packet, interface, 3, 0);
        return;
      }

      struct sr_if* outgoing_interface = sr_get_interface(sr, entry->interface);
      memcpy(eth_hdr->ether_shost, outgoing_interface->addr, ETHER_ADDR_LEN);

      ip_hdr->ip_ttl--;
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));

      struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, entry->gw.s_addr, packet, len, entry->interface);
      handle_arpreq(req, &sr->cache, sr);
    }

    else if (bool_tipInInterface(sr, ip_hdr->ip_dst) == 1) {
      
      if (ip_hdr->ip_p == ip_protocol_icmp) {
        struct sr_icmp_t08_hdr* icmp_hdr = packet + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr);

        if (icmp_hdr->icmp_type != 8) {
          return;
        }

        uint16_t icmp_storedCkSum = icmp_hdr->icmp_sum;
        icmp_hdr->icmp_sum = 0;

        if (cksum(icmp_hdr, ( len - sizeof(struct sr_ethernet_hdr) - sizeof(struct sr_ip_hdr)) ) != icmp_storedCkSum) {
          return;
        }
        
        icmp_echoReply(sr, packet, len, interface);
      }
    }
  }
}