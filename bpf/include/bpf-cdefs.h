#ifndef __F4_BPF_CDEFS_H__ 
#define __F4_BPF_CDEFS_H__

#include <linux/pkt_cls.h>
#include <stdio.h>
#include "bpf-dbg.h"
#include "bpf-f4.h"

#define DP_IFI(md) (((struct __sk_buff *)md)->ifindex)
#define DP_IIFI(md) (((struct __sk_buff *)md)->ingress_ifindex)
#define DP_OIFI(md) (((struct __sk_buff *)md)->ifindex)
#define DP_PDATA(md) (((struct __sk_buff *)md)->data)
#define DP_PDATA_END(md) (((struct __sk_buff *)md)->data_end)
#define DP_MDATA(md) (((struct __sk_buff *)md)->data_meta)
#define DP_GET_LEN(md) (((struct __sk_buff *)md)->len)

#define F4_PPLN_RDR(F)      (F->pm.pipe_act |= F4_PIPE_RDR);
#define F4_PPLN_RDR_PRIO(F) (F->pm.pipe_act |= F4_PIPE_RDR_PRIO);
#define F4_PPLN_REWIRE(F)   (F->pm.pipe_act |= F4_PIPE_REWIRE);
#define F4_PPLN_SETCT(F)    (F->pm.pipe_act |= F4_PIPE_SET_CT);

#define DP_F4_IS_EGR(md) (0)

#define DP_REDIRECT TC_ACT_REDIRECT
#define DP_DROP     TC_ACT_SHOT
#define DP_PASS     TC_ACT_OK

#define F4_PPLN_PASSC(F, C)         \
do {                                \
  F->pm.pipe_act |= F4_PIPE_PASS;   \
  F->pm.rcode |= C;                 \
} while (0)

#define F4_PPLN_DROPC(F, C)         \
do {                                \
  F->pm.pipe_act |= F4_PIPE_DROP;   \
  F->pm.rcode |= C;                 \
} while (0)

#define F4_PPLN_TRAPC(F,C)          \
do {                                \
  F->pm.pipe_act |= F4_PIPE_TRAP;   \
  F->pm.rcode = C;                  \
} while (0)

static __u32 __always_inline
dp_get_pkt_hash(void *md)
{
  bpf_set_hash_invalid(md);
  return bpf_get_hash_recalc(md);
}

static int __always_inline
dp_add_l2(void *md, int delta)
{
  return bpf_skb_change_head(md, delta, 0);
}

static int __always_inline
dp_remove_l2(void *md, int delta)
{
  return bpf_skb_adjust_room(md, -delta, BPF_ADJ_ROOM_MAC, 
                        BPF_F_ADJ_ROOM_FIXED_GSO);
}

static int __always_inline
dp_buf_add_room(void *md, int delta, __u64 flags)
{
  return bpf_skb_adjust_room(md, delta, BPF_ADJ_ROOM_MAC,
                            flags);
}

static int __always_inline
dp_buf_delete_room(void *md, int delta, __u64 flags)
{
  return bpf_skb_adjust_room(md, -delta, BPF_ADJ_ROOM_MAC, 
                            flags);
}

static int __always_inline
dp_redirect_port(void *tbl, struct xfrm *xf)
{
  return bpf_redirect_map(tbl, xf->pm.oport, 0);
}

static int __always_inline
dp_set_tcp_src_ip(void *md, struct xfrm *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int tcp_csum_off = xf->pm.l4_off + offsetof(struct tcphdr, check);
  int ip_src_off = xf->pm.l3_off + offsetof(struct iphdr, saddr);
  __be32 old_sip = xf->l34m.saddr4;

  bpf_l4_csum_replace(md, tcp_csum_off, old_sip, xip, BPF_F_PSEUDO_HDR |sizeof(xip));
  bpf_l3_csum_replace(md, ip_csum_off, old_sip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_src_off, &xip, sizeof(xip), 0);

  xf->l34m.saddr4 = xip;

  return 0;
}

static int __always_inline
dp_set_tcp_dst_ip(void *md, struct xfrm *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int tcp_csum_off = xf->pm.l4_off + offsetof(struct tcphdr, check);
  int ip_dst_off = xf->pm.l3_off + offsetof(struct iphdr, daddr);
  __be32 old_dip = xf->l34m.daddr4;

  bpf_l4_csum_replace(md, tcp_csum_off, old_dip, xip, BPF_F_PSEUDO_HDR | sizeof(xip));
  bpf_l3_csum_replace(md, ip_csum_off, old_dip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_dst_off, &xip, sizeof(xip), 0);
  xf->l34m.daddr4 = xip;

  return 0;
}

static int __always_inline
dp_set_tcp_sport(void *md, struct xfrm *xf, __be16 xport)
{
  int tcp_csum_off = xf->pm.l4_off + offsetof(struct tcphdr, check);
  int tcp_sport_off = xf->pm.l4_off + offsetof(struct tcphdr, source);
  __be32 old_sport = xf->l34m.source;

  if (xf->l34m.frg || !xport) return 0;

  bpf_l4_csum_replace(md, tcp_csum_off, old_sport, xport, sizeof(xport));
  bpf_skb_store_bytes(md, tcp_sport_off, &xport, sizeof(xport), 0);
  xf->l34m.source = xport;

  return 0;
}

static int __always_inline
dp_set_tcp_dport(void *md, struct xfrm *xf, __be16 xport)
{
  int tcp_csum_off = xf->pm.l4_off + offsetof(struct tcphdr, check);
  int tcp_dport_off = xf->pm.l4_off + offsetof(struct tcphdr, dest);
  __be32 old_dport = xf->l34m.dest;

  if (xf->l34m.frg) return 0;

  bpf_l4_csum_replace(md, tcp_csum_off, old_dport, xport, sizeof(xport));
  bpf_skb_store_bytes(md, tcp_dport_off, &xport, sizeof(xport), 0);
  xf->l34m.dest = xport;

  return 0;
}

static int __always_inline
dp_set_udp_src_ip(void *md, struct xfrm *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int udp_csum_off = xf->pm.l4_off + offsetof(struct udphdr, check);
  int ip_src_off = xf->pm.l3_off + offsetof(struct iphdr, saddr);
  __be32 old_sip = xf->l34m.saddr4;
  
  bpf_l4_csum_replace(md, udp_csum_off, old_sip, xip, BPF_F_PSEUDO_HDR |sizeof(xip));
  bpf_l3_csum_replace(md, ip_csum_off, old_sip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_src_off, &xip, sizeof(xip), 0);
  xf->l34m.saddr4 = xip;

  return 0;
}

static int __always_inline
dp_set_udp_dst_ip(void *md, struct xfrm *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int udp_csum_off = xf->pm.l4_off + offsetof(struct udphdr, check);
  int ip_dst_off = xf->pm.l3_off + offsetof(struct iphdr, daddr);
  __be32 old_dip = xf->l34m.daddr4;

  bpf_l4_csum_replace(md, udp_csum_off, old_dip, xip, BPF_F_PSEUDO_HDR | sizeof(xip));
  bpf_l3_csum_replace(md, ip_csum_off, old_dip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_dst_off, &xip, sizeof(xip), 0);
  xf->l34m.daddr4 = xip;

  return 0;
}

static int __always_inline
dp_set_udp_sport(void *md, struct xfrm *xf, __be16 xport)
{
  int udp_csum_off = xf->pm.l4_off + offsetof(struct udphdr, check);
  int udp_sport_off = xf->pm.l4_off + offsetof(struct udphdr, source);
  __be32 old_sport = xf->l34m.source;

  if (xf->l34m.frg || !xport) return 0;

  bpf_l4_csum_replace(md, udp_csum_off, old_sport, xport, sizeof(xport));
  bpf_skb_store_bytes(md, udp_sport_off, &xport, sizeof(xport), 0);
  xf->l34m.source = xport;

  return 0;
}

static int __always_inline
dp_set_udp_dport(void *md, struct xfrm *xf, __be16 xport)
{
  int udp_csum_off = xf->pm.l4_off + offsetof(struct udphdr, check);
  int udp_dport_off = xf->pm.l4_off + offsetof(struct udphdr, dest);
  __be32 old_dport = xf->l34m.dest;

  if (xf->l34m.frg) return 0;

  bpf_l4_csum_replace(md, udp_csum_off, old_dport, xport, sizeof(xport));
  bpf_skb_store_bytes(md, udp_dport_off, &xport, sizeof(xport), 0);
  xf->l34m.dest = xport;

  return 0;
}

static int __always_inline
dp_set_icmp_src_ip(void *md, struct xfrm *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int ip_src_off = xf->pm.l3_off + offsetof(struct iphdr, saddr);
  __be32 old_sip = xf->l34m.saddr4;
 
  bpf_l3_csum_replace(md, ip_csum_off, old_sip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_src_off, &xip, sizeof(xip), 0);
  xf->l34m.saddr4 = xip;

  return 0;
}

static int __always_inline
dp_set_icmp_dst_ip(void *md, struct xfrm *xf, __be32 xip)
{
  int ip_csum_off  = xf->pm.l3_off + offsetof(struct iphdr, check);
  int ip_dst_off = xf->pm.l3_off + offsetof(struct iphdr, daddr);
  __be32 old_dip = xf->l34m.daddr4;
  
  bpf_l3_csum_replace(md, ip_csum_off, old_dip, xip, sizeof(xip));
  bpf_skb_store_bytes(md, ip_dst_off, &xip, sizeof(xip), 0);
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