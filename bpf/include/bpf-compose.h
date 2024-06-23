#ifndef __F4_BPF_COMPOSE_H__ 
#define __F4_BPF_COMPOSE_H__
/*
* Kernel eBPF packet eBPF packet composer/decomposer
*/

#include <linux/if_packet.h>
#include "bpf-dbg.h"
#include "bpf-cdefs.h"
#include "bpf-nat.h"

/* IP flags */
#define IP_CE		  0x8000		/* Flag: "Congestion"		*/
#define IP_DF		  0x4000		/* Flag: "Don't Fragment"	*/
#define IP_MF		  0x2000		/* Flag: "More Fragments"	*/
#define IP_OFFSET	0x1FFF		/* "Fragment Offset" part	*/

static __always_inline int ip_is_fragment(const struct iphdr *iph)
{
	return (iph->frag_off & htons(IP_MF | IP_OFFSET)) != 0;
}

static __always_inline int ip_is_last_fragment(const struct iphdr *iph)
{
	return (iph->frag_off & htons(IP_MF)) == 0;
}

static __always_inline int ip_is_first_fragment(const struct iphdr *iph)
{
	return (iph->frag_off & htons(IP_OFFSET)) == 0;
}

static __always_inline int proto_is_vlan(__be16 h_proto)
{
	return !!(h_proto == htons(ETH_P_8021Q) ||
		  h_proto == htons(ETH_P_8021AD));
}

/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
  __be32 check = iph->check;
  check += htons(0x0100);
  iph->check = (__be16)(check + (check >= 0xFFFF));
  return --iph->ttl;
}

static inline int ipv6_addr_is_multicast(const struct in6_addr *addr)
{
  return (addr->s6_addr32[0] & htonl(0xFF000000)) == htonl(0xFF000000);
}

static int __always_inline
dp_pkt_is_l2mcbc(struct xfrm *xf, void *md)
{
  struct __sk_buff *b = md;  

  if (b->pkt_type == PACKET_MULTICAST ||
      b->pkt_type == PACKET_BROADCAST) {
    return 1;
  }
  return 0;
}

static int __always_inline
dp_parse_eth(struct parser *p,
             void *md,
             struct xfrm *xf)
{
  struct ethhdr *eth;
  eth = DP_TC_PTR(p->dbegin);

  if ((void *)(eth + 1) > p->dend) {
    return DP_PRET_FAIL;
  }

  if (p->in_pkt) {
    xf->il2m.valid = 1;
    memcpy(xf->il2m.dl_dst, eth->h_dest, 2*6);
    memcpy(xf->pm.lkup_dmac, eth->h_dest, 6);
    xf->il2m.dl_type = eth->h_proto;
  } else {
    xf->l2m.valid = 1;
    memcpy(xf->l2m.dl_dst, eth->h_dest, 2*6);
    memcpy(xf->pm.lkup_dmac, eth->h_dest, 6);
    xf->l2m.dl_type = eth->h_proto;
  }

  if (!ETH_TYPE_ETH2(eth->h_proto)) {
    return DP_PRET_PASS;
  }

  p->dbegin = DP_ADD_PTR(eth, sizeof(*eth));

  return DP_PRET_OK;
}

static int __always_inline
dp_parse_arp(struct parser *p,
             void *md,
             struct xfrm *xf)
{
  struct arp_ethhdr *arp = DP_TC_PTR(p->dbegin);

  if ((void *)(arp + 1) > p->dend) {
      return DP_PRET_FAIL;
  }

  if (p->in_pkt) {
    if (arp->ar_pro == htons(ETH_P_IP) && 
        arp->ar_pln == 4) {
      xf->il34m.saddr4 = arp->ar_spa;
      xf->il34m.daddr4 = arp->ar_tpa;
    }
    xf->il34m.nw_proto = ntohs(arp->ar_op) & 0xff;
  } else {
    if (arp->ar_pro == htons(ETH_P_IP) && 
        arp->ar_pln == 4) {
      xf->l34m.saddr4 = arp->ar_spa;
      xf->l34m.daddr4 = arp->ar_tpa;
    }
    xf->l34m.nw_proto = ntohs(arp->ar_op) & 0xff;
  }

  return DP_PRET_TRAP;
}

static int __always_inline
dp_parse_tcp(struct parser *p,
             void *md,
             struct xfrm *xf)
{
  struct tcphdr *tcp = DP_TC_PTR(p->dbegin);
  __u8 tcp_flags = 0;

  if ((void *)(tcp + 1) > p->dend) {
    /* In case of fragmented packets */
    return DP_PRET_OK;
  }

  if (tcp->fin)
    tcp_flags = F4_TCP_FIN;
  if (tcp->rst)
    tcp_flags |= F4_TCP_RST;
  if (tcp->syn)
    tcp_flags |= F4_TCP_SYN;
  if (tcp->psh)
    tcp_flags |= F4_TCP_PSH;
  if (tcp->ack)
    tcp_flags |= F4_TCP_ACK;
  if (tcp->urg)
    tcp_flags |= F4_TCP_URG;

  if (p->in_pkt) {
    if (tcp_flags & (F4_TCP_FIN|F4_TCP_RST)) {
      xf->pm.il4fin = 1;
    }

    xf->il34m.source = tcp->source;
    xf->il34m.dest = tcp->dest;
    xf->il34m.seq = tcp->seq;
    xf->pm.itcp_flags = tcp_flags;
  } else {
    if (tcp_flags & (F4_TCP_FIN|F4_TCP_RST)) {
      xf->pm.l4fin = 1;
    }

    xf->l34m.source = tcp->source;
    xf->l34m.dest = tcp->dest;
    xf->l34m.seq = tcp->seq;
    xf->pm.tcp_flags = tcp_flags;
  }

  return DP_PRET_OK;
}

static int __always_inline
dp_parse_icmp(struct parser *p,
              void *md,
              struct xfrm *xf)
{
  struct icmphdr *icmp = DP_TC_PTR(p->dbegin);

  if ((void *)(icmp + 1) > p->dend) {
    return DP_PRET_OK;
  }

  if ((icmp->type == ICMP_ECHOREPLY ||
    icmp->type == ICMP_ECHO)) {
    if (p->in_pkt) {
      xf->il34m.source = icmp->un.echo.id;
      xf->il34m.dest = icmp->un.echo.id;
    } else {
      xf->l34m.source = icmp->un.echo.id;
      xf->l34m.dest = icmp->un.echo.id;
    }
  }
  return DP_PRET_OK;
}

static int __always_inline
dp_parse_udp(struct parser *p,
             void *md,
             struct xfrm *xf)
{
  struct udphdr *udp = DP_TC_PTR(p->dbegin);
  
  if ((void *)(udp + 1) > p->dend) {
    return DP_PRET_OK;
  }

  xf->l34m.source = udp->source;
  xf->l34m.dest = udp->dest;

  return DP_PRET_OK;
}

static int __always_inline
dp_parse_icmp6(struct parser *p,
               void *md,
               struct xfrm *xf)
{
  struct icmp6hdr *icmp6 = DP_TC_PTR(p->dbegin);

  if ((void *)(icmp6 + 1) > p->dend) {
    return DP_PRET_OK;
  }

  if ((icmp6->icmp6_type == ICMPV6_ECHO_REPLY ||
      icmp6->icmp6_type == ICMPV6_ECHO_REQUEST)) {
    if (p->in_pkt) {
      xf->il34m.source = icmp6->icmp6_dataun.u_echo.identifier;
      xf->il34m.dest = icmp6->icmp6_dataun.u_echo.identifier;
    } else {
      xf->l34m.source = icmp6->icmp6_dataun.u_echo.identifier;
      xf->l34m.dest = icmp6->icmp6_dataun.u_echo.identifier;
    }
  } else if (icmp6->icmp6_type >= 133 &&
            icmp6->icmp6_type <= 137) {
    return DP_PRET_PASS;
  }

  return DP_PRET_OK;
}

static int __always_inline
dp_parse_ipv4(struct parser *p,
              void *md,
              struct xfrm *xf)
{
  struct iphdr *iph = DP_TC_PTR(p->dbegin);
  int iphl = iph->ihl << 2;

  if ((void *)(iph + 1) > p->dend) {
    return DP_PRET_FAIL;
  }

  if (DP_ADD_PTR(iph, iphl) > p->dend) {
    return DP_PRET_FAIL;
  }

  if (xf->pm.igr) {
    __u8 *hit;
    hit = bpf_map_lookup_elem(&f4gw_igr_ipv4, &iph->daddr);
    if(hit != NULL) {
      bpf_tail_call(md, &f4gw_progs, F4_DP_PASS_PGM_ID);
    }
  } else if(xf->pm.egr) {
    __u8 *hit;
    hit = bpf_map_lookup_elem(&f4gw_egr_ipv4, &iph->daddr);
    if(hit != NULL) {
      bpf_tail_call(md, &f4gw_progs, F4_DP_PASS_PGM_ID);
    }
  }

  xf->pm.l3_len = ntohs(iph->tot_len);
  xf->pm.l3_plen = xf->pm.l3_len - iphl;

  xf->l34m.valid = 1;
  xf->l34m.tos = iph->tos & 0xfc;
  xf->l34m.nw_proto = iph->protocol;
  xf->l34m.saddr4 = iph->saddr;
  xf->l34m.daddr4 = iph->daddr;

  if (ip_is_first_fragment(iph)) {
    xf->pm.l4_off = DP_DIFF_PTR(DP_ADD_PTR(iph, iphl), p->start);
    p->dbegin = DP_ADD_PTR(iph, iphl);

    if (ip_is_fragment(iph)) {
      xf->l2m.ssnid = iph->id;
      xf->pm.goct = 1;
    }

    if (xf->l34m.nw_proto == IPPROTO_TCP) {
      return dp_parse_tcp(p, md, xf);
    } else if (xf->l34m.nw_proto == IPPROTO_UDP) {
      return dp_parse_udp(p, md, xf);
    } else if (xf->l34m.nw_proto == IPPROTO_ICMP) {
      return dp_parse_icmp(p, md, xf);
    } 
  } else {
    if (ip_is_fragment(iph)) {
      xf->l34m.source = iph->id;
      xf->l34m.dest = iph->id;
      xf->l2m.ssnid = iph->id;
      xf->l34m.frg = 1;
    }
  }

  return DP_PRET_OK;
}

static int __always_inline
dp_parse_ipv6(struct parser *p,
              void *md,
              struct xfrm *xf)
{
  struct ipv6hdr *ip6 = DP_TC_PTR(p->dbegin);

  if ((void *)(ip6 + 1) > p->dend) {
    return DP_PRET_FAIL;
  }

  if (ipv6_addr_is_multicast(&ip6->daddr) ||
      ipv6_addr_is_multicast(&ip6->saddr)) {
    return DP_PRET_PASS;
  }

  xf->pm.l3_plen = ntohs(ip6->payload_len);
  xf->pm.l3_len =  xf->pm.l3_plen + sizeof(*ip6);

  xf->l34m.valid = 1;
  xf->l34m.tos = ((ip6->priority << 4) |
               ((ip6->flow_lbl[0] & 0xf0) >> 4)) & 0xfc;
  xf->l34m.nw_proto = ip6->nexthdr;
  memcpy(&xf->l34m.saddr, &ip6->saddr, sizeof(ip6->saddr));
  memcpy(&xf->l34m.daddr, &ip6->daddr, sizeof(ip6->daddr));

  xf->pm.l4_off = DP_DIFF_PTR(DP_ADD_PTR(ip6, sizeof(*ip6)), p->start);
  p->dbegin = DP_ADD_PTR(ip6, sizeof(*ip6));

  if (xf->l34m.nw_proto == IPPROTO_TCP) {
    return dp_parse_tcp(p, md, xf);
  } else if (xf->l34m.nw_proto == IPPROTO_UDP) {
    return dp_parse_udp(p, md, xf);
  } else if (xf->l34m.nw_proto == IPPROTO_ICMPV6) {
    return dp_parse_icmp6(p, md, xf);
  }
  return DP_PRET_OK;
}

static int __always_inline
dp_parse_d0(void *md,
            struct xfrm *xf,
            int skip_v6)
{
  int ret = 0;
  struct parser p;

  p.in_pkt = 0;
  p.skip_l2 = 0;
  p.skip_v6 = skip_v6;
  p.start = DP_TC_PTR(DP_PDATA(md));
  p.dbegin = DP_TC_PTR(p.start);
  p.dend = DP_TC_PTR(DP_PDATA_END(md));
  
  xf->pm.py_bytes = DP_DIFF_PTR(p.dend, p.dbegin);

  if ((ret = dp_parse_eth(&p, md, xf))) {
    goto handle_excp;
  }


  xf->pm.l3_off = DP_DIFF_PTR(p.dbegin, p.start);

  if (xf->l2m.dl_type == htons(ETH_P_ARP)) {
    ret = dp_parse_arp(&p, md, xf);
  } else if (xf->l2m.dl_type == htons(ETH_P_IP)) {
    ret = dp_parse_ipv4(&p, md, xf);
  } else if (xf->l2m.dl_type == htons(ETH_P_IPV6)) {
    if (p.skip_v6 == 1) {
      return 0;
    }
    ret = dp_parse_ipv6(&p, md, xf);
  } 
  // else if (xf->l2m.dl_type == htons(ETH_P_F4)) {
  //   ret = dp_parse_f4(&p, md, xf);
  // }

  if (ret != 0) {
    goto handle_excp;
  }

  return 0;

handle_excp:
  if (ret > DP_PRET_OK) {
    F4_PPLN_PASSC(xf, F4_PIPE_RC_PARSER);
  } else if (ret < DP_PRET_OK) {
    F4_PPLN_DROPC(xf, F4_PIPE_RC_PARSER);
  }
  return ret;
}

static int __always_inline
dp_unparse_packet_always(void *ctx,  struct xfrm *xf)
{
  if (xf->pm.nf & F4_NAT_SRC && xf->nm.dsr == 0) {
    if (xf->l2m.dl_type == ntohs(ETH_P_IPV6) || xf->nm.nv6) {
      // dp_sunp_tcall(ctx, xf);
    } else {
      if (dp_do_snat(ctx, xf) != 0) {
        return DP_DROP;
      }
    }
  } else if (xf->pm.nf & F4_NAT_DST && xf->nm.dsr == 0) {
    if (xf->l2m.dl_type == ntohs(ETH_P_IPV6)) {
      // dp_sunp_tcall(ctx, xf);
    } else {
      if (dp_do_dnat(ctx, xf) != 0) {
        return DP_DROP;
      }
    }
  }

  return 0;
}

static int __always_inline
dp_unparse_packet(void *ctx,  struct xfrm *xf)
{
  return dp_do_out(ctx, xf);
}

#endif