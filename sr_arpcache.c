#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"

// void table_lookup(struct sr_instance* sr, uint32_t ip, uint32_t* next_hop_ip, char** out_iface){
  
//   struct sr_rt* entry = sr->routing_table;

//   while(entry!=NULL){

//     if(entry->dest.s_addr == ip){

//       if(next_hop_ip)*next_hop_ip = entry->gw.s_addr;

//       if(out_iface)*out_iface = entry->interface;

//       return;
//     }
//     entry=entry->next;
//   }

//   *next_hop_ip = 0;
//   *out_iface = NULL;
// }

// ! CHANGED
void table_lookup(struct sr_instance* sr, uint32_t ip, uint32_t* next_hop_ip, char** out_iface) {
    
    struct sr_rt* entry = sr->routing_table;
    struct sr_rt* best_match = NULL;
    int curr_largest_len = -1;

    while (entry != NULL) {
        uint32_t target_prefix = ip & entry->mask.s_addr;
        uint32_t entry_prefix = entry->dest.s_addr & entry->mask.s_addr;

        if (target_prefix == entry_prefix) {
            int subnet_length = __builtin_popcount(entry->mask.s_addr);

            if (subnet_length > curr_largest_len) {
                best_match = entry;
                curr_largest_len = subnet_length;
            }
        }
        entry = entry->next;
    }

    if (best_match) {
        if (next_hop_ip) *next_hop_ip = best_match->gw.s_addr;
        if (out_iface) *out_iface = best_match->interface;
    } else {
        if (next_hop_ip) *next_hop_ip = 0;
        if (out_iface) *out_iface = NULL;
    }
}


void icmp_hostUnreachable(struct sr_instance *sr, struct sr_packet* packet) {

    unsigned int len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr) + sizeof(struct sr_icmp_t11_hdr);
    uint8_t* buf = malloc(len);

    struct sr_ethernet_hdr* packet_eth_head = (struct sr_ethernet_hdr *) packet->buf;
    struct sr_ip_hdr* packet_ip_head = (struct sr_ip_hdr *) (packet->buf + sizeof(struct sr_ethernet_hdr));

    struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr *) buf;
    memcpy(eth_hdr->ether_dhost, packet_eth_head->ether_shost, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, packet_eth_head->ether_dhost, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_ip);

    struct sr_ip_hdr* ip_hdr = (struct sr_ip_hdr *) (buf + sizeof(struct sr_ethernet_hdr));
    memcpy(ip_hdr, packet_ip_head, sizeof(sr_ip_hdr_t));
    ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(struct sr_icmp_t11_hdr));
    ip_hdr->ip_ttl = INIT_TTL;
    ip_hdr->ip_p = ip_protocol_icmp;
    ip_hdr->ip_dst = packet_ip_head->ip_src;

    uint32_t next_hop_ip;
    char* entry;
    table_lookup(sr, ip_hdr->ip_src, &next_hop_ip, &entry);

    if (entry == NULL) {
        return;
    }

    ip_hdr->ip_src = sr_get_interface(sr, entry)->ip;

    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(struct sr_ip_hdr));

    struct sr_icmp_t11_hdr* icmp_hdr = (struct sr_icmp_t11_hdr *) (buf + sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_ip_hdr));
    icmp_hdr->icmp_type = 3; 
    icmp_hdr->icmp_code = 1;
    icmp_hdr->unused = 0;
    memcpy(icmp_hdr->data, packet_ip_head, ICMP_DATA_SIZE);

    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(struct sr_icmp_t11_hdr));
    memcpy(eth_hdr->ether_shost, sr_get_interface(sr, entry)->addr, ETHER_ADDR_LEN);

    // struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, next_hop_ip, buf, len, entry);
    // handle_arpreq(req, &sr->cache, sr);

    // ! CHANGED
    struct sr_arpentry* entryCache = sr_arpcache_lookup(&sr->cache, next_hop_ip);

    if (entryCache != NULL) {
      memcpy(eth_hdr->ether_dhost, entryCache->mac, ETHER_ADDR_LEN);
      sr_send_packet(sr, buf, len, entry);
      free(entryCache);
    }

    else {
        struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, next_hop_ip, buf, len, entry);
        handle_arpreq(req, &sr->cache, sr);
    }
}

void arp_SendRequest(struct sr_instance *sr, struct sr_arpreq* request, struct sr_packet* packet) {

    unsigned int len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arp_hdr);
    uint8_t* buf = malloc(len);

    struct sr_if* pkt_Interface = sr_get_interface(sr, packet->iface);

    struct sr_ethernet_hdr* eth_hdr = (struct sr_ethernet_hdr*) buf;
    
    memcpy(eth_hdr->ether_dhost, (uint8_t[]){255, 255, 255, 255, 255, 255}, ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, pkt_Interface->addr, ETHER_ADDR_LEN);
    eth_hdr->ether_type = htons(ethertype_arp);

    struct sr_arp_hdr* arp_hdr = (struct sr_arp_hdr *) (buf + sizeof(struct sr_ethernet_hdr));
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = sizeof(uint32_t);
    arp_hdr->ar_op = htons(arp_op_request);
    memcpy(arp_hdr->ar_sha, pkt_Interface->addr, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = pkt_Interface->ip;
    memcpy(arp_hdr->ar_tha, (unsigned char[]){0, 0, 0, 0, 0, 0}, ETHER_ADDR_LEN);
    arp_hdr->ar_tip = request->ip;

    sr_send_packet(sr, buf, len, packet->iface);
}

void handle_arpreq(struct sr_arpreq *req, struct sr_arpcache *cache, struct sr_instance *sr) {
    
    time_t now = time(NULL);

    if (difftime(now, req->sent) >= 1.0) {

        struct sr_packet *pkt = req->packets;

        if (req->times_sent >= 5) {

            while (pkt) {

                struct sr_packet *next_pkt = pkt->next;

                icmp_hostUnreachable(sr, pkt);

                pkt = next_pkt;
                // free(pkt);
            }

            sr_arpreq_destroy(&sr->cache, req);

        } else {

            arp_SendRequest(sr, req, pkt);
            req->sent = time(NULL);
            req->times_sent++;
        }
    }
}

void sr_arpcache_sweepreqs(struct sr_instance *sr) { 

    struct sr_arpreq *req = sr->cache.requests;
    struct sr_arpreq *next_req = NULL;

    while (req != NULL) {

        next_req = req->next;
        handle_arpreq(req, &sr->cache, sr);
        req = next_req;
    }
}


// -----------------------------------------------------------------------------------------------------
// DO NOT PASS
// -----------------------------------------------------------------------------------------------------

// -----------------------------------------------------------------------------------------------------
// DO NOT PASS
// -----------------------------------------------------------------------------------------------------

// -----------------------------------------------------------------------------------------------------
// DO NOT PASS
// -----------------------------------------------------------------------------------------------------


/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP req to the ARP req queue. If the req is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP req. You should free the passed *packet.
   
   A pointer to the ARP req is returned; it should not be freed. The caller
   can remove the ARP req from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this req */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the req queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp req entry. If this arp req
   entry is on the arp req queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}