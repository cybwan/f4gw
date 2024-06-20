#ifndef __F4_BPF_CDEFS_H__ 
#define __F4_BPF_CDEFS_H__

#include <linux/pkt_cls.h>
#include "bpf-dbg.h"
#include "bpf-f4.h"

#define DP_IFI(md) (((struct xdp_md *)md)->ingress_ifindex)
#define DP_IIFI(md) (((struct xdp_md *)md)->ingress_ifindex)
#define DP_OIFI(md) (0)
#define DP_PDATA(md) (((struct xdp_md *)md)->data)
#define DP_PDATA_END(md) (((struct xdp_md *)md)->data_end)
#define DP_MDATA(md) (((struct xdp_md *)md)->data_meta)
#define DP_GET_LEN(md)  ((((struct xdp_md *)md)->data_end) - \
                         (((struct xdp_md *)md)->data)) \

#define F4_PPLN_RDR(F)      (F->pm.pipe_act |= F4_PIPE_RDR);
#define F4_PPLN_RDR_PRIO(F) (F->pm.pipe_act |= F4_PIPE_RDR_PRIO);
#define F4_PPLN_REWIRE(F)   (F->pm.pipe_act |= F4_PIPE_REWIRE);
#define F4_PPLN_SETCT(F)    (F->pm.pipe_act |= F4_PIPE_SET_CT);

#define DP_F4_IS_EGR(md) (0)

#define DP_REDIRECT XDP_REDIRECT
#define DP_DROP     XDP_DROP
#define DP_PASS     XDP_PASS

#define F4_PPLN_PASSC(F, C)          \
do {                                  \
  F->pm.pipe_act |= F4_PIPE_PASS;    \
  F->pm.rcode |= C;                   \
} while (0)

#define F4_PPLN_DROPC(F, C)         \
do {                                  \
  F->pm.pipe_act |= F4_PIPE_DROP;    \
  F->pm.rcode |= C;                   \
} while (0)

#define F4_PPLN_TRAPC(F,C)          \
do {                                  \
  F->pm.pipe_act |= F4_PIPE_TRAP;    \
  F->pm.rcode = C;                    \
} while (0)

static __always_inline
__u16 sdbm(__u8 *ptr, __u8 len)
{
  __u64 hash = 0;
  __u8 c;
  
#pragma clang loop unroll(full)
  for(__u8 n = 0; n < len; n++) {
      c = ptr[n];
      // hash = c & 0xff + (hash << 6) + (hash << 16) - hash;
  }

  return (__u16)(hash & 0xffff);
}

static __always_inline
__u32 dp_get_pkt_hash(struct xfrm *xf)
{
  struct dp_t4 h = { 
    .saddr = xf->l34m.saddr4, 
    .daddr = xf->l34m.daddr4, 
    .source = xf->l34m.source, 
    .dest = xf->l34m.dest };
  return sdbm((__u8 *)&h, sizeof(struct dp_t4));
}

static __always_inline
__u16 dp_csum_fold_helper(__u32 csum)
{
    __u32 sum;
    sum = (csum >> 16) + (csum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

static __always_inline
__u16 dp_ipv4_checksum_diff(__u16 seed, struct iphdr *new, struct iphdr *old)
{
    __u32 csum, size = sizeof(struct iphdr);   
    csum = bpf_csum_diff((__be32 *)old, size, (__be32 *)new, size, seed);
    return dp_csum_fold_helper(csum);
}

static __always_inline
__u16 dp_icmp_checksum_diff(__u16 seed, struct icmphdr *new, struct icmphdr *old)
{
    __u32 csum, size = sizeof(struct icmphdr);   
    csum = bpf_csum_diff((__be32 *)old, size, (__be32 *)new, size, seed);
    return dp_csum_fold_helper(csum);
}

static __always_inline __u16
dp_l4_checksum_diff(__u16 seed, struct dp_t4 *new, struct dp_t4 *old) {
    __u32 csum, size = sizeof(struct dp_t4);
    csum = bpf_csum_diff((__be32 *)old, size, (__be32 *)new, size, seed);
    return dp_csum_fold_helper(csum);
}

static __always_inline __u16
dp_l4_addr_checksum_diff(__u16 seed, struct dp_t2_addr *new, struct dp_t2_addr *old) {
    __u32 csum, size = sizeof(struct dp_t2_addr);
    csum = bpf_csum_diff((__be32 *)old, size, (__be32 *)new, size, seed);
    return dp_csum_fold_helper(csum);
}

static __always_inline __u16
dp_l4_port_checksum_diff(__u16 seed, struct dp_t2_port *new, struct dp_t2_port *old) {
    __u32 csum, size = sizeof(struct dp_t2_port);
    csum = bpf_csum_diff((__be32 *)old, size, (__be32 *)new, size, seed);
    return dp_csum_fold_helper(csum);
}

static int __always_inline
dp_add_l2(void *md, int delta)
{
  return bpf_xdp_adjust_head(md, -delta);
}

static int __always_inline
dp_remove_l2(void *md, int delta)
{
  return bpf_xdp_adjust_head(md, delta);
}

static int __always_inline
dp_buf_add_room(void *md, int delta, __u64 flags)
{
  return bpf_xdp_adjust_head(md, -delta);
}

static int __always_inline
dp_buf_delete_room(void *md, int delta, __u64 flags)
{
  return bpf_xdp_adjust_head(md, delta);
}

static int __always_inline
dp_redirect_port(void *tbl, struct xfrm *xf)
{
  return bpf_redirect_map(tbl, xf->pm.oport, 0);
}

static int __always_inline
dp_set_tcp_src_ip(void *md, struct xfrm *xf, __be32 xip)
{
  void *dend = DP_TC_PTR(DP_PDATA_END(md));

  struct iphdr *iph = DP_TC_PTR(DP_PDATA(md) + xf->pm.l3_off);
  if ((void *)(iph + 1) > dend)  {
    F4_PPLN_DROPC(xf, F4_PIPE_RC_PLRT_ERR);
    return -1;
  }

  struct tcphdr *tcp = DP_ADD_PTR(DP_PDATA(md), xf->pm.l4_off);
  if ((void *)(tcp + 1) > dend) {
    F4_PPLN_DROPC(xf, F4_PIPE_RC_PLERR);
    return -1;
  }

  struct dp_t2_addr o = {.daddr = xf->l34m.daddr4, .saddr = xf->l34m.saddr4};
  struct dp_t2_addr n = {.daddr = xf->l34m.daddr4, .saddr = xip};
  tcp->check = dp_l4_addr_checksum_diff(~(tcp->check), &n, &o);

  __u16 old_csum = iph->check;
  iph->check = 0;
  struct iphdr old = *iph;
  iph->saddr = xip;
  iph->daddr = xf->l34m.daddr4;
  iph->check = dp_ipv4_checksum_diff(~old_csum, iph, &old);

  xf->l34m.saddr4 = xip;

  return 0;
}

static int __always_inline
dp_set_tcp_dst_ip(void *md, struct xfrm *xf, __be32 xip)
{
  void *dend = DP_TC_PTR(DP_PDATA_END(md));

  struct iphdr *iph = DP_TC_PTR(DP_PDATA(md) + xf->pm.l3_off);
  if ((void *)(iph + 1) > dend)  {
    F4_PPLN_DROPC(xf, F4_PIPE_RC_PLRT_ERR);
    return -1;
  }

  struct tcphdr *tcp = DP_ADD_PTR(DP_PDATA(md), xf->pm.l4_off);
  if ((void *)(tcp + 1) > dend) {
    F4_PPLN_DROPC(xf, F4_PIPE_RC_PLERR);
    return -1;
  }

  struct dp_t2_addr o = {.saddr = xf->l34m.saddr4, .daddr = xf->l34m.daddr4};
  struct dp_t2_addr n = {.saddr = xf->l34m.saddr4, .daddr = xip};
  tcp->check = dp_l4_addr_checksum_diff(~(tcp->check), &n, &o);

  __u16 old_csum = iph->check;
  iph->check = 0;
  struct iphdr old = *iph;
  iph->saddr = xf->l34m.saddr4;
  iph->daddr = xip;
  iph->check = dp_ipv4_checksum_diff(~old_csum, iph, &old);

  xf->l34m.daddr4 = xip;

  return 0;
}

static int __always_inline
dp_set_tcp_sport(void *md, struct xfrm *xf, __be16 xport)
{
  void *dend = DP_TC_PTR(DP_PDATA_END(md));

  struct tcphdr *tcp = DP_ADD_PTR(DP_PDATA(md), xf->pm.l4_off);
  if ((void *)(tcp + 1) > dend) {
    F4_PPLN_DROPC(xf, F4_PIPE_RC_PLERR);
    return -1;
  }

  struct dp_t2_port o = {.dest = xf->l34m.dest, .source = xf->l34m.source};
  struct dp_t2_port n = {.dest = xf->l34m.dest, .source = xport};
  tcp->check = dp_l4_port_checksum_diff(~(tcp->check), &n, &o);
  tcp->source = xport;

  xf->l34m.source = xport;

  return 0;
}

static int __always_inline
dp_set_tcp_dport(void *md, struct xfrm *xf, __be16 xport)
{
  void *dend = DP_TC_PTR(DP_PDATA_END(md));

  struct tcphdr *tcp = DP_ADD_PTR(DP_PDATA(md), xf->pm.l4_off);
  if ((void *)(tcp + 1) > dend) {
    F4_PPLN_DROPC(xf, F4_PIPE_RC_PLERR);
    return -1;
  }

  struct dp_t2_port o = {.source = xf->l34m.source, .dest = xf->l34m.dest};
  struct dp_t2_port n = {.source = xf->l34m.source, .dest = xport};
  tcp->check = dp_l4_port_checksum_diff(~(tcp->check), &n, &o);
  tcp->dest = xport;

  xf->l34m.dest = xport;

  return 0;
}

static int __always_inline
dp_set_udp_src_ip(void *md, struct xfrm *xf, __be32 xip)
{
  void *dend = DP_TC_PTR(DP_PDATA_END(md));

  struct iphdr *iph = DP_TC_PTR(DP_PDATA(md) + xf->pm.l3_off);
  if ((void *)(iph + 1) > dend)  {
    F4_PPLN_DROPC(xf, F4_PIPE_RC_PLRT_ERR);
    return -1;
  }

  struct udphdr *udp = DP_ADD_PTR(DP_PDATA(md), xf->pm.l4_off);
  if ((void *)(udp + 1) > dend) {
    F4_PPLN_DROPC(xf, F4_PIPE_RC_PLERR);
    return -1;
  }

  struct dp_t2_addr o = {.daddr = xf->l34m.daddr4, .saddr = xf->l34m.saddr4};
  struct dp_t2_addr n = {.daddr = xf->l34m.daddr4, .saddr = xip};
  udp->check = dp_l4_addr_checksum_diff(~(udp->check), &n, &o);

  __u16 old_csum = iph->check;
  iph->check = 0;
  struct iphdr old = *iph;
  iph->saddr = xip;
  iph->daddr = xf->l34m.daddr4;
  iph->check = dp_ipv4_checksum_diff(~old_csum, iph, &old);

  xf->l34m.saddr4 = xip;

  return 0;
}

static int __always_inline
dp_set_udp_dst_ip(void *md, struct xfrm *xf, __be32 xip)
{
  void *dend = DP_TC_PTR(DP_PDATA_END(md));

  struct iphdr *iph = DP_TC_PTR(DP_PDATA(md) + xf->pm.l3_off);
  if ((void *)(iph + 1) > dend)  {
    F4_PPLN_DROPC(xf, F4_PIPE_RC_PLRT_ERR);
    return -1;
  }

  struct udphdr *udp = DP_ADD_PTR(DP_PDATA(md), xf->pm.l4_off);
  if ((void *)(udp + 1) > dend) {
    F4_PPLN_DROPC(xf, F4_PIPE_RC_PLERR);
    return -1;
  }

  struct dp_t2_addr o = {.saddr = xf->l34m.saddr4, .daddr = xf->l34m.daddr4};
  struct dp_t2_addr n = {.saddr = xf->l34m.saddr4, .daddr = xip};
  udp->check = dp_l4_addr_checksum_diff(~(udp->check), &n, &o);

  __u16 old_csum = iph->check;
  iph->check = 0;
  struct iphdr old = *iph;
  iph->saddr = xf->l34m.saddr4;
  iph->daddr = xip;
  iph->check = dp_ipv4_checksum_diff(~old_csum, iph, &old);

  xf->l34m.daddr4 = xip;

  return 0;
}

static int __always_inline
dp_set_udp_sport(void *md, struct xfrm *xf, __be16 xport)
{
  void *dend = DP_TC_PTR(DP_PDATA_END(md));

  struct udphdr *udp = DP_ADD_PTR(DP_PDATA(md), xf->pm.l4_off);
  if ((void *)(udp + 1) > dend) {
    F4_PPLN_DROPC(xf, F4_PIPE_RC_PLERR);
    return -1;
  }

  struct dp_t2_port o = {.dest = xf->l34m.dest, .source = xf->l34m.source};
  struct dp_t2_port n = {.dest = xf->l34m.dest, .source = xport};
  udp->check = dp_l4_port_checksum_diff(~(udp->check), &n, &o);
  udp->source = xport;

  xf->l34m.source = xport;

  return 0;
}

static int __always_inline
dp_set_udp_dport(void *md, struct xfrm *xf, __be16 xport)
{
  void *dend = DP_TC_PTR(DP_PDATA_END(md));

  struct udphdr *udp = DP_ADD_PTR(DP_PDATA(md), xf->pm.l4_off);
  if ((void *)(udp + 1) > dend) {
    F4_PPLN_DROPC(xf, F4_PIPE_RC_PLERR);
    return -1;
  }

  struct dp_t2_port o = {.dest = xf->l34m.dest, .source = xf->l34m.source};
  struct dp_t2_port n = {.dest = xport, .source = xf->l34m.source};
  udp->check = dp_l4_port_checksum_diff(~(udp->check), &n, &o);
  udp->dest = xport;

  xf->l34m.dest = xport;

  return 0;
}

static int __always_inline
dp_set_icmp_src_ip(void *md, struct xfrm *xf, __be32 xip)
{
  void *dend = DP_TC_PTR(DP_PDATA_END(md));

  struct iphdr *iph = DP_TC_PTR(DP_PDATA(md) + xf->pm.l3_off);
  if ((void *)(iph + 1) > dend)  {
    F4_PPLN_DROPC(xf, F4_PIPE_RC_PLRT_ERR);
    return -1;
  }

  struct icmphdr *icmp = DP_ADD_PTR(DP_PDATA(md), xf->pm.l4_off);
  if ((void *)(icmp + 1) > dend) {
    F4_PPLN_DROPC(xf, F4_PIPE_RC_PLERR);
    return -1;
  }

  __u16 old_icmp_csum = icmp->checksum;
  icmp->checksum = 0; 
  struct icmphdr old_icmp = *icmp;
  icmp->checksum = dp_icmp_checksum_diff(~old_icmp_csum, icmp, &old_icmp);

  __u16 old_csum = iph->check;
  iph->check = 0;
  struct iphdr old = *iph;
  iph->saddr = xip;
  iph->daddr = xf->l34m.daddr4;
  iph->check = dp_ipv4_checksum_diff(~old_csum, iph, &old);

  xf->l34m.saddr4 = xip;

  return 0;
}

static int __always_inline
dp_set_icmp_dst_ip(void *md, struct xfrm *xf, __be32 xip)
{
  void *dend = DP_TC_PTR(DP_PDATA_END(md));

  struct iphdr *iph = DP_TC_PTR(DP_PDATA(md) + xf->pm.l3_off);
  if ((void *)(iph + 1) > dend)  {
    F4_PPLN_DROPC(xf, F4_PIPE_RC_PLRT_ERR);
    return -1;
  }

  struct icmphdr *icmp = DP_ADD_PTR(DP_PDATA(md), xf->pm.l4_off);
  if ((void *)(icmp + 1) > dend) {
    F4_PPLN_DROPC(xf, F4_PIPE_RC_PLERR);
    return -1;
  }

  __u16 old_icmp_csum = icmp->checksum;
  icmp->checksum = 0; 
  struct icmphdr old_icmp = *icmp;
  icmp->checksum = dp_icmp_checksum_diff(~old_icmp_csum, icmp, &old_icmp);

  __u16 old_csum = iph->check;
  iph->check = 0;
  struct iphdr old = *iph;
  iph->saddr = xf->l34m.saddr4;
  iph->daddr = xip;
  iph->check = dp_ipv4_checksum_diff(~old_csum, iph, &old);

  xf->l34m.daddr4 = xip;

  return 0;
}

static int __always_inline
dp_do_out(void *ctx, struct xfrm *xf)
{
  void *start = DP_TC_PTR(DP_PDATA(ctx));
  void *dend = DP_TC_PTR(DP_PDATA_END(ctx));
  struct ethhdr *eth;
  int vlan;

  vlan = xf->pm.bd;

  if (vlan == 0) {
    /* Strip existing vlan. Nothing to do if there was no vlan tag */
    if (xf->l2m.vlan[0] != 0) {
      // if (dp_remove_vlan_tag(ctx, xf) != 0) {
      //   F4_PPLN_DROPC(xf, F4_PIPE_RC_PLERR);
      //   return -1;
      // }
    } else {
      if (start + sizeof(*eth) > dend) {
        F4_PPLN_DROPC(xf, F4_PIPE_RC_PLERR);
        return -1;
      }
      eth = DP_TC_PTR(DP_PDATA(ctx));
      memcpy(eth->h_dest, xf->l2m.dl_dst, 6);
      memcpy(eth->h_source, xf->l2m.dl_src, 6);
    }
    return 0;
  } else {
    /* If existing vlan tag was present just replace vlan-id, else 
     * push a new vlan tag and set the vlan-id
     */
    eth = DP_TC_PTR(DP_PDATA(ctx));
    if (xf->l2m.vlan[0] != 0) {
      // if (dp_swap_vlan_tag(ctx, xf, vlan) != 0) {
      //   F4_PPLN_DROPC(xf, F4_PIPE_RC_PLERR);
      //   return -1;
      // }
    } else {
      // if (dp_insert_vlan_tag(ctx, xf, vlan) != 0) {
      //   F4_PPLN_DROPC(xf, F4_PIPE_RC_PLERR);
      //   return -1;
      // }
    }
  }

  return 0;
}

static int __always_inline
dp_tail_call(void *ctx,  struct xfrm *xf, void *fa, __u32 idx)
{
  int z = 0;

  if (xf->nm.ct_sts != 0) {
    return DP_PASS;
  }

#ifdef HAVE_DP_FC
  /* fa state can be reused */ 
  bpf_map_update_elem(&fcas, &z, fa, BPF_ANY);
#endif

  /* xfi state can be reused */ 
  bpf_map_update_elem(&f4gw_xfrms, &z, xf, BPF_ANY);

  bpf_tail_call(ctx, &f4gw_progs, idx);

  return DP_PASS;
}

static int __always_inline
dp_spin_lock(struct bpf_spin_lock *lock) {
#ifndef F4_SPIN_LOCK_OFF
  bpf_spin_lock(lock);
#endif
  // __sync_fetch_and_add(&lock->val, 1);
  return 0;
}

static int __always_inline
dp_spin_unlock(struct bpf_spin_lock *lock) {
#ifndef F4_SPIN_LOCK_OFF
  bpf_spin_unlock(lock);
#endif
  // __sync_lock_release(&lock->val);
  return 0;
}

#endif