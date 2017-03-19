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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* Added constant definitions */
#define MAX_IP 255
#define protocal_addr 4
#define SMALL_SUB 8
#define IP_HDR_MIN 5
#define TTL 64
/* Added helper functions */

/* **** helper1: sr_send_arp_req **********
 * Consume:
 *  1. sr_instance sr: the sr instance used
 *  2. uint32_t req_ip: the ip address sending request to
 * Action:
 * send a arp request to the destination ip of the request.
 * if ip is not in routing table, do nothing but print error
 */
 void sr_send_arp_req(struct sr_instance* sr, uint32_t *req_ip){
    char* iface = NULL;
    struct sr_rt* cur = sr->routing_table;
    while(cur){
      if(cur->gw.s_addr == req_ip){
        iface = cur->interface;
        break;
      }
      cur = cur->next;
    }
    if(!iface){
      fprintf(stderr, "ERROR: request ip address not in routing table\n", );
    } else {
      uint8_t addr_all[ETHER_ADDR_LEN];
      int i;
      for(i = 0; i < addr_all.size(); i++) addr_all[i] = MAX_IP;
      sr_send_arp(sr, arp_op_request, iface, (unsigned char*) addr_all, req_ip);
      /* helper2 is called */
    }

}/* ---helper1: sr_send_arp_req--- */

/* **** helper2: sr_send_arp **********
 * Consume:
 *  1. sr_instance sr: the sr instance used
 *  2. enum sr_arp_opcode opcode: request or reply
 *  3. char* iface: interface of the target ip
 *  3. unsigned char* target_addr: destination address
 *  4. uint32_t target_ip: the destination ip address 
 * Action:
 * send a arp to the destination ip of the request
 */
void sr_send_arp(struct sr_instance *sr, enum sr_arp_opcode opcode, char* iface, unsigned char* target_addr, uint32_t target_ip){
  sr_arp_hdr_t * arp_hdr = malloc(sizeof(sr_arp_hdr_t));
  if(!arp_hdr){
    fprintf(stderr, "ERROR: memory allocation for arp_hdr failed\n");
    return;
  }
  /* define arp_hdr */
  arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
  arp_hdr->ar_pro = htons(ethertype_ip);
  arp_hdr->ar_hln = ETHER_ADDR_LEN;
  arp_hdr->ar_pln = protocal_addr;
  arp_hdr->ar_op = htons(opcode);

  /* find record for iface */
  struct sr_if* iface_rec = sr_get_interface(sr, iface);
  if(!iface_rec){
    fprintf(stderr, "ERROR: sorry, not record for the interface\n");
    return;
  }
  /* put sender's info into arp_hdr */
  memcpy(arp_hdr->ar_sha, iface_rec->addr, ETHER_ADDR_LEN);
  arp_hdr->ar_sip = iface_rec->ip;
  /* put target's info into arp_hdr */
  memcpy(arp_hdr->ar_tha, target_addr, ETHER_ADDR_LEN);
  arp_hdr->ar_tip = target_ip;

  /* helper 3 is called */
  sr_send_ether(sr, (uint8_t *) arp_hdr, iface, (uint8_t *)target_addr, ethertype_arp);
  
  /* free */
  free(arp_hdr);

} /* ---helper2:sr_send_arp---*/

/* ********* helper3:sr_send_ether ***********************
 * Consume:
 * 1. struct sr_instance sr: sr
 * 2. uint8_t hdr: the source hdr
 * 3. char* iface: iface
 * 4. uint8_t * target_addr: destination address
 * 5. sr_ethertype etype: arp or ip
 * Action:
 * add an ethernet header to hdr, combine into a big header,
 * then send by sr_send_packet.
 * P.S.:
 * look for sr_send_packet in sr_vns_comm.c
 */
  void sr_send_ether(struct sr_instance sr, uint8_t hdr, char* iface, uint8_t* target_addr, enum sr_ethertype etype){
    
    /* prepare ethernet header ether_hdr */
    sr_ethernet_hdr_t* ether_hdr = malloc(sizeof(sr_ethernet_hdr_t));
    ether_hdr->ether_type = htons(etype);
    memcpy(ether_hdr->ether_dhost, target_addr, ETHER_ADDR_LEN);

    struct sr_if* if_cur = sr->if_list;
    while(if_cur){
      if(strcmp(if_cur->name, iface) == 0){
        memcpy(ether_hdr->ether_shost, if_cur->addr, ETHER_ADDR_LEN);
        break;
      }
      if_cur = if_cur->next;
    }
    if(!ether_hdr->ether_shost){
      fprintf(stderr, "ERROR: sr_send_ether, iface is not in sr if_list\n", );
      return;
    }

    /* combine into a big header */
    uint8_t* big_hdr = malloc(sizeof(hdr) + sizeof(sr_ethernet_hdr_t));
    memcpy(big_hdr, ether_hdr, sizeof(sr_ethernet_hdr_t));
    memcpy(big_hdr + sizeof(sr_ethernet_hdr_t), hdr, sizeof(hdr));
    
    /* send */
    sr_send_packet(sr, eth, (uint8_t *) (sizeof(hdr) + sizeof(sr_ethernet_hdr_t)), iface);

    /* free */
    free(ether_hdr);
    free(big_hdr);

  } /*---helper3: sr_send_ether---*/

/* *********** helper4: sr_send_icmp_t3 ******************
 * Consumes:
 * 1. struct sr_instance* sr: sr
 * 2. struct sr_packet* pkt: the target packet
 * 3. enum sr_icmp_type type: type of icmp type 3 is sending (defined in <protocal.h>)
 *      Type 3: icmp_type_unreachable
 * 4. enum sr_icmp_code code: code for icmp (defined in <protocol.h>)
 * Action:
 * send icmp packet of type 3 to source addr of pkt
 * Note:
 * packet->buf has 2 segments, which is sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), 
 * the (sr_ip_hdr_t) part will be the data part when building the sr_icmp_t3_hdr icmp
 */
void sr_send_icmp_t3(struct sr_instance* sr, struct sr_packet* pkt, enum sr_icmp_type type, enum sr_icmp_code code){
  sr_icmp_t3_hdr_t* icmp = malloc(sizeof(sr_icmp_t3_hdr_t));
  /* data */
  sr_ip_hdr_t* data = pkt->buf + sizeof(sr_ethernet_hdr_t);
  memcpy(icmp->data, (uint8_t *) data, 4 * (data->ip_hl) + SMALL_SUB);
  /* other parts */
  icmp->icmp_type = type;
  icmp->icmp_code = code;
  icmp->icmp_sum = 0;
  icmp->icmp_sum = cksum(icmp, sizeof(sr_icmp_t3_hdr_t));

  /* helper5 is called */
  sr_send_ip_pkt(sr, icmp, sizeof(icmp), sr_get_interface(sr, pkt->iface)->ip, data->ip_src);

  /* free */
  free(icmp);
  
}/*---sr_send_icmp_t3---*/

/* *********** helper5: sr_send_ip_pkt ******************
 * Consumes:
 * 1. struct sr_instance* sr: sr
 * 2. uint8_t* buf: source data, can be a sr_icmp_t3_hdr_t, or sr_icmp_hdr_t
 * 3. unsigned int len: sizeof(buf)
 * 4. uint32_t src: source IP address
 * 5. uint32_t dest: destination IP address
 * Action:
 * send the packet to the target IP address
 */
void sr_send_ip_pkt(struct sr_instance* sr, uint8_t* buf, unsigned int len, uint32_t src, uint32_t dest){
  struct sr_rt * rt_cur = longest_prefix_match(sr, dest); /* helper6 called */
  if(!rt_cur){
    fprintf(stderr, "ERROR: sr_send_ip_pkt, longest_prefix_match returns NULL\n");
    return;
  }
  struct sr_if* iface sr_get_interface(sr, rt_cur->interface);
  if(!iface){
    fprintf(stderr, "ERROR: sr_send_ip_pkt, sr_get_interface returns NULL\n");
    return;
  }

  struct sr_ethernet_hdr* ether = calloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + len, sizeof(uint8_t));
  struct sr_ip_hdr* ip = ether + sizeof(sr_ethernet_hdr_t);
  /* write buf */
  memcpy(ip + 1, buf, len);
  /* write ip_hdr */
  ip->ip_hl = IP_HDR_MIN;
  ip->ip_v = ip_v;

  ip->ip_len = htons(sizeof(sr_ip_hdr_t) + len);
  ip->ip_off = htons(IP_DF);

  ip->ip_ttl = TTL;
  ip->ip_p = ip_protocol_icmp;
  ip->ip_sum = 0;
  ip->ip_sum = cksum(ip, sizeof(sr_ip_hdr_t));
  ip->ip_src = src;
  ip->ip_dst = dest;
  /* write sr_ethernet_hdr_t */
  ether->ether_type = htons(ethertype_ip);
  memcpy(eth->ether_shost, if_node->addr, ETHER_ADDR_LEN);

  /* send */
  sr_send_packet_helper(sr, (uint8_t *) ether, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + len,
    iface->name, rt_cur->gw.s_addr); /* helper7 called */

  /* free */
  free(ether);
}/*---helper5: sr_send_ip_pkt---*/

/* *********** helper6: longest_prefix_match ******************
 * Consumes:
 * 1. struct sr_instance* sr: sr
 * 2. uint32_t dst: the destination ip address
 * Return: 
 * struct sr_rt : a matched routing table in sr that matches ip dst
 */
struct sr_rt* longest_prefix_match(struct sr_instance* sr, uint32_t dst){
  struct sr_rt* cur = sr->routing_table
  struct sr_rt* ret = NULL;

  struct in_addr max_mask;
  max_mask.s_addr = 0;

  while(cur){
    uint32_t tmp = cur->mask.s_addr & dst;

    if(tmp == cur->dest.s_addr){

      if(ntohl(cur->mask.s_addr) >= ntohl(max_mask.s_addr)){
        max_mask = cur->mask;
        ret = cur;
      }

    }
  }

  return ret;
} /*---helper6: longest-prefix-match---*/

/* *********** helper7: sr_send_packet_helper ******************
 * Consumes:
 * 1. struct sr_instance sr: sr
 * 2. uint8_t* buf: buf send to the destination
 * 3. unsigned int len: sizeof(buf)
 * 4. const char* iface: interface sent
 * The 4 variables above are exactly same as sr_send_packet
 * 5. uint32_t dst_ip: the destination ip address used to check
 * Action:
 * A helper for sr_send_packet, look for ip address in arp cache
 * before the packet is sent, if nothing found in the cache, add
 * the pkt to arp queue instead.
 */
void sr_send_packet_helper(struct sr_instance* sr, uint8_t* buf, unsigned int len, 
                    const char* iface, uint32_t dst_ip){
  struct sr_arpentry* arp_en = sr_arpcache_lookup(&(sr->cache), dst_ip);

  if(arp_en){

    unsigned char* mac_addr = arp_en->mac;
    memcpy( ((sr_ethernet_hdr_t *) buf)->ether_dhost, mac_addr, ETHER_ADDR_LEN);
    /* send */
    sr_send_packet(sr, buf, len, iface);
    /* free */
    free(arp_en);

  } else {
    fprintf(stderr, "ERROR: sr_send_packet_helper, cannot find arp entry\n");
    /* add the pkt to arp queue */
    struct sr_arpreq* req = sr_arpcache_queuereq(&(sr->cache), dst_ip, buf, len, iface);
    handle_arpreq(sr, req);
  }
} /*---helper7: sr_send_packet_helper---*/

/* ************** helper8: sr_handle_ip *****************************
 *
 * Consumes: 
 *
 * 1. sr_instance sr: sr
 * 2. uint8_t pkt: the packet to handle
 * 3. unsigned int len: length of pkt
 * 4. char* interface: the interface 
 * same variables as sr_handlepacket
 *
 * Actions:
 *
 * Help sr_handlepacket to handle a IP packet, do the following steps:
 * 1. Check where pkt is destined, if is for router's IP, go to step 2,
 *    else, use normal forwarding logic to forward pkt
 * 2. If pkt is an ICMP echo request, checksum, then send an ICMP echo reply
 *    to the sending host
 *    If pkt contains a TCP or UDP payload, send an ICMP port unreachable to the
 *    sending host
 *    O.w., ignore pkt
 * 
 */
void sr_handle_ip(struct sr_instance* sr, uint8_t * pkt, unsigned int len, char* interface){
  
  /* check length */
 if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    fprintf(stderr, "ERROR: IP Packet length less than minimum length, exit\n");
    return;
  }
  print_hdrs(packet, len);

  sr_ip_hdr_t *ip_hdr = pkt + sizeof(sr_ethernet_hdr_t);
  unsigned int ip_hdr_len = ip_hdr->ip_hl * 4;

  /* where is it detined? */
  struct sr_if* if_cur = sr->if_list;
  while(if_cur){
    if(if_cur->ip == ip_hdr->ip_dst) break;
    if_cur = if_cur->next;
  } 

  if(if_cur){
    /* okay, it's for me :) */
    printf("Packet is for router...\n");

    sr_handle_ip_router(sr, pkt); /* helper 9 called */
    return;
  }

  /* fine, it's not for me :( */
  if(ip_hdr->ip_ttl - 1 == 0){
    /* haha, timeout! for nobody */
    fprintf(stderr, "ERROR: TTL is 0, sending icmp back to host....\n");
    uint8_t* buf = malloc(ip_hdr_len + 4 + SMALL_SUB);
    memcpy(buf + 4, ip_hdr, ip_hdr_len + SMALL_SUB);

    /* send */
    sr_send_icmp(); /* helper 10 is called */

    /* free */
    free(buf);
    return;
  }

  /* I will figure out where it's for ~~ =3 */
  ip_hdr->ip_ttl--;

  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr_len);

  struct sr_rt* lpm = longest_prefix_match(sr, ip_hdr->ip_dst);

  if(lpm){
    uint8_t* tmp = malloc(len);

    if(!tmp){
      fprintf(stderr, "ERROR: sr_handle_ip, malloc failed\n");
      return;
    }

    memcpy(tmp, packet, len);
    struct sr_ethernet_hdr* ether_hdr = (sr_ethernet_hdr_t *) tmp;
    struct sr_if* iface = sr_get_interface(sr, lpm->interface);
    memcpy(ether_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    free(tmp);

  } else {
    fprintf(stderr, "ERROR: no routing table for the ip, sending icmp...\n");
    struct sr_if* iface = sr_get_interface(sr, interface);
    sr_send_icmp_t3(sr, packet, icmp_type_unreachable, icmp_code_net_unreach);
    /* helper 4 called */
  }

} /*---helper8: sr_handle_ip---*/

/* ************** helper 9: sr_handle_ip_router ************ 
 * Consumes:
 * 1. struct sr_instance* sr: sr
 * 2. struct sr_packet pkt: the ip packet handling
 * Actions:
 * Help sr_handle_ip to handle the ip packet for router, do followings:
 * 1. If ICMP echo request, checksum, send ICMP reply
 * 2. If contains TCP/UDP payload, send ICMP port unreachable back
 * 3. O.w. ignore
 */

 void sr_handle_ip_router(struct sr_instance* sr, struct sr_packet pkt){
  sr_ip_hdr_t* hdr = pkt + sizeof(sr_ethernet_hdr_t);
  unsigned int len = hdr->ip_hl * 4;
  uint8_t* payload = ((uint8_t *) hdr) + len;
  struct sr_icmp_hdr* icmp_hdr = payload;

  if(hdr->ip_p == ip_protocol_icmp && icmp_hdr->icmp_type == icmp_type_echo_req){

    /* icmp echo request, send icmp reply*/
    sr_send_icmp(sr, pkt, icmp_type_echo_reply, icmp_code_other); /* helper 10 called */

  } else {

    /* TCP or UDP */
    printf("Cannot process UDP or TCP packet, sending icmp port unreachable....");
    sr_send_icmp_t3(sr, pkt, icmp_type_unreachable, icmp_code_port_unreach);

  }
 } /*---helper9: sr_handle_ip_router---*/

/* ***************** helper 10: sr_send_icmp **************
 * Consumes:
 * 1. struct sr_instance* sr: sr
 * 2. struct sr_packet* pkt: the target packet
 * 3. enum sr_icmp_type type: icmp type sending
 * 4. enum sr_icmp_code code: icmp code sending
 * Action:
 * send a non-type3 icmp to the host sent pkt
 */ 

void sr_send_icmp(struct sr_instance* sr, struct sr_packet* pkt, enum sr_icmp_type type, enum sr_icmp_code code){
  struct sr_ip_hdr* ip_hdr = pkt + sizeof(sr_ethernet_hdr_t);
  unsigned int ip_hdr_len = ip_hdr->ip_hl * 4;
  unsigned int icmp_len = ntohs(ip_hdr->ip_len) - ip_hdr_len;

  /* prepare icmp */
  struct sr_icmp_hdr* icmp = calloc(icmp_len, 1);
  memcpy(icmp + 1, buf, icmp_len - sizeof(sr_icmp_hdr_t));
  icmp->icmp_type = type;
  icmp->icmp_code = code;
  icmp->icmp_sum = 0;
  icmp->icmp_sum = cksum(icmp, icmp_len);

  /* send */
  sr_send_ip_pkt(sr, icmp, icmp_len, ip_hdr->ip_dst, ip_hdr->src);

  /* free */
  free(icmp);

} /*---helper10: sr_send_icmp---*/
/* ****** Pseudo-code in sr_arpcache.h 
function handle_arpreq(req):
       if difftime(now, req->sent) > 1.0
           if req->times_sent >= 5:
               send icmp host unreachable to source addr of all pkts waiting
                 on this request
               arpreq_destroy(req)
           else:
               send arp request
               req->sent = now
               req->times_sent++

   --
*/
/* *********************************************************
 * Function Name: handle_arpreq
 * Type: Global
 * Consume: sr_instance sr, struct sr_arpreq req
 * Action: see pseudo-code above
 * *********************************************************
 */

void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req){
    time_t time_cur = time(NULL);

    if(difftime(time_cur, req->sent) > 1.0){
      if(req->times_sent >= 5){

        fprintf(stderr, "ERROR: request sent 5 times, sending icmp unreachable and destroying\n", );
        
        /* send icmp host unreachable to source addr of all pkts waiting on this request */
        struct sr_packet* pkts_cur = req->packets;

        while(pkts_cur){
          sr_send_icmp_t3(sr, pkts_cur, icmp_unreachable, icmp_code_host_unreach); /* helper4 called */
          pkts_cur = pkts_cur->next;
        }

        arpreq_destroy(req);
      } else {

      /* send arp req */
      sr_send_arp_req(sr, req->ip); /* helper1 is called */

      req->sent = now;
      req->times_sent++;
    }
  }
} /*----- handle_arpreq -----*/




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
    
    /* No Additional initialization code added */

} /* -- sr_init -- */

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
 * by sr_vns_comm.c that means do NOT free either (signified by "lent" comment).  
 * Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d\n",len);

  /* Forwarding logic here */

  uint16_t pkt_type = ethertype(packet);

  if(pkt_type == ethertype_ip){

    /* handle ip packet */
    sr_handle_ip(sr, packet, len, interface);/* helper 8 called */ 

  } else if(pkt_type == ethertype_arp){

    /* handle arp packet */
    sr_handle_arp(sr, packet, len, interface); /* helper X called */

  } else { 

    fprintf(stderr, "ERROR: the packet is neither IP not ARP\n");

  }
  

}/* -- sr_handlepacket -- */

