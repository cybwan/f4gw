#ifndef __F4_BPF_LB_H__ 
#define __F4_BPF_LB_H__

#include "bpf-dbg.h"

static int __always_inline
dp_pipe_set_nat(void *ctx, struct xfrm *xf, 
                struct dp_nat_act *na, int do_snat)
{
  xf->pm.nf = do_snat ? F4_NAT_SRC : F4_NAT_DST;
  DP_XADDR_CP(xf->nm.nxip, na->xip);
  DP_XADDR_CP(xf->nm.nrip, na->rip);
  DP_XMAC_CP(xf->nm.nxmac, na->xmac);
  DP_XMAC_CP(xf->nm.nrmac, na->rmac);
  xf->nm.nxifi = na->xifi;
  xf->nm.nxport = na->xport;
  xf->nm.nrport = na->rport;
  xf->nm.nv6 = na->nv6 ? 1 : 0;
  xf->nm.dsr = na->dsr;
  xf->nm.cdis = na->cdis;
  return 0;
}

static int __always_inline
dp_sel_nat_ep(void *ctx, struct xfrm *xf, struct dp_nat_tacts *act)
{
  int sel = -1;
  __u8 n = 0;
  __u16 i = 0;
  struct dp_xfrm_inf *nxfrm_act;
  __u16 rule_num = act->ca.cidx;

  if (act->sel_type == NAT_LB_SEL_RR) {
    dp_spin_lock(&act->lock);
    i = act->sel_hint; 

    while (n < F4_MAX_NXFRMS) {
      if (i >= 0 && i < F4_MAX_NXFRMS) {
        nxfrm_act = &act->nxfrms[i];
        if (nxfrm_act->inactive == 0) {
          act->sel_hint = (i + 1) % act->nxfrm;
          sel = i;
          break;
        }
      }
      i++;
      i = i % act->nxfrm;
      n++;
    }
    dp_spin_unlock(&act->lock);
  } else if (act->sel_type == NAT_LB_SEL_HASH) {
    sel = dp_get_pkt_hash(ctx) % act->nxfrm;
    if (sel >= 0 && sel < F4_MAX_NXFRMS) {
      /* Fall back if hash selection gives us a deadend */
      if (act->nxfrms[sel].inactive) {
        for (i = 0; i < F4_MAX_NXFRMS; i++) {
          if (act->nxfrms[i].inactive == 0) {
            sel = i;
            break;
          }
        }
      }
    }
  } else if (act->sel_type == NAT_LB_SEL_RR_PERSIST) {
    __u64 now = bpf_ktime_get_ns();
    __u64 base;
    __u64 tfc = 0;

    dp_spin_lock(&act->lock);
    if (act->base_to == 0 || now - act->lts > act->pto) {
      act->base_to = (now/act->pto) * act->pto;
    }
    base = act->base_to;
    if (act->pto) {
      tfc = base/act->pto;
    } else {
      act->pto = NAT_LB_PERSIST_TIMEOUT;
      tfc = base/NAT_LB_PERSIST_TIMEOUT;
    }
    sel = (xf->l34m.saddr4 & 0xff) ^  ((xf->l34m.saddr4 >> 24) & 0xff) ^ (tfc & 0xff);
    sel %= act->nxfrm;
    act->lts = now;
    dp_spin_unlock(&act->lock);
  } else if (act->sel_type == NAT_LB_SEL_LC) {
    struct dp_nat_epacts *epa;
    __u32 key = rule_num;
    __u32 lc = 0;
    epa = bpf_map_lookup_elem(&f4gw_nat_ep, &key);
    if (epa != NULL) {
      epa->ca.act_type = DP_SET_NACT_SESS;
      dp_spin_lock(&epa->lock);
      for (i = 0; i < F4_MAX_NXFRMS; i++) {
        __u32 as = epa->active_sess[i];
        if (sel < 0) {
          sel = i;
          lc = as;
        } else {
          if (lc > as) {
            sel = i;
            lc = as;
          }
        }
      }
      if (sel >= 0 && sel < F4_MAX_NXFRMS) {
        epa->active_sess[sel]++;
      }
      dp_spin_unlock(&epa->lock);
    }
  }

  return sel;
}

static int __always_inline
dp_do_nat(void *ctx, struct xfrm *xf)
{
  struct dp_nat_key key;
  struct dp_xfrm_inf *nxfrm_act;
  struct dp_nat_tacts *act;
  int sel;

  memset(&key, 0, sizeof(key));
  DP_XADDR_CP(key.daddr, xf->l34m.daddr);
  if (xf->l34m.nw_proto != IPPROTO_ICMP) {
    key.dport = xf->l34m.dest;
  } else {
    key.dport = 0;
  }
  key.zone = xf->pm.zone;
  key.l4proto = xf->l34m.nw_proto;
  key.mark = (__u16)(xf->pm.dp_mark & 0xffff);
  if (xf->l2m.dl_type == ntohs(ETH_P_IPV6)) {
    key.v6 = 1;
  }

  memset(&key, 0, sizeof(key));
  key.l4proto = xf->l34m.nw_proto;
  key.v6 = 0;

  act = bpf_map_lookup_elem(&f4gw_nat, &key);
  if (!act) {
    /* Default action - Nothing to do */
    xf->pm.nf &= ~F4_NAT_DST;
    return 0;
  }

  if (act->ca.act_type == DP_SET_SNAT || 
      act->ca.act_type == DP_SET_DNAT) {
    sel = dp_sel_nat_ep(ctx, xf, act);

    xf->nm.dsr = act->ca.oaux ? 1: 0;
    xf->nm.cdis = act->cdis ? 1: 0;
    xf->pm.nf = act->ca.act_type == DP_SET_SNAT ? F4_NAT_SRC : F4_NAT_DST;

    /* FIXME - Do not select inactive end-points 
     * Need multi-passes for selection
     */
    if (sel >= 0 && sel < F4_MAX_NXFRMS) {
      nxfrm_act = &act->nxfrms[sel];

      DP_XADDR_CP(xf->nm.nxip, nxfrm_act->nat_xip);
      DP_XADDR_CP(xf->nm.nrip, nxfrm_act->nat_rip);
      DP_XMAC_CP(xf->nm.nxmac, nxfrm_act->nat_xmac);
      DP_XMAC_CP(xf->nm.nrmac, nxfrm_act->nat_rmac);
      xf->nm.nxifi = nxfrm_act->nat_xifi;
      xf->nm.nrport = nxfrm_act->nat_rport;
      if(nxfrm_act->nat_xport) {
        xf->nm.nxport = nxfrm_act->nat_xport;
      } else {
        xf->nm.nxport = xf->l34m.source;
      }

      xf->nm.nv6 = nxfrm_act->nv6 ? 1: 0;
      xf->nm.sel_aid = sel;
      xf->nm.ito = act->ito;
      xf->pm.rule_id =  act->ca.cidx;

      /* Special case related to host-dnat */
      if (xf->l34m.saddr4 == xf->nm.nxip4 && xf->pm.nf == F4_NAT_DST) {
        xf->nm.nxip4 = 0;
      }
    } else {
      xf->pm.nf = 0;
    }
  } else { 
    F4_PPLN_DROPC(xf, F4_PIPE_RC_ACT_UNK);
  }

  // xf->f4m.l4proto = xf->l34m.nw_proto;
  // xf->f4m.daddr4 = xf->l34m.daddr4;
  // xf->f4m.saddr4 = xf->l34m.saddr4;
  // xf->f4m.xaddr4 = xf->nm.nxip4;
  // xf->f4m.dport = xf->l34m.dest;
  // xf->f4m.sport = xf->l34m.source;
  // xf->f4m.xport = xf->nm.nxport;

  // if ( xf->pm.igr == 1 && \
  //   xf->l2m.dl_type == ntohs(ETH_P_IP) && \
  //   xf->l34m.nw_proto == IPPROTO_TCP && \
  //   xf->l34m.saddr4 == 367175872 && \
  //   xf->l34m.daddr4 == 3305231619 && \
  //   xf->l34m.dest == htons(80) ) {
  //   debug_printf("tc_ingress dp_do_nat saddr4 %u daddr4 %u\n", xf->l34m.saddr4, xf->l34m.daddr4);
  //   debug_printf("tc_ingress dp_do_nat nxip4 %u nxport %u\n", xf->nm.nxip4, ntohs(xf->nm.nxport));
  //   debug_printf("tc_ingress dp_do_nat nrip4 %u nrport %u\n", xf->nm.nrip4, ntohs(xf->nm.nrport));
  //   debug_printf("tc_ingress dp_do_nat sport %u dport %u\n", ntohs(xf->l34m.source), ntohs(xf->l34m.dest));
  // }

  // if ( xf->pm.egr == 1 && \
  //   xf->l2m.dl_type == ntohs(ETH_P_IP) && \
  //   xf->l34m.nw_proto == IPPROTO_TCP && \
  //   xf->l34m.saddr4 == 551725248 && \
  //   xf->l34m.daddr4 == 367175872 && \
  //   xf->l34m.source == htons(8689) ) {
  //   debug_printf("tc_egress dp_do_nat saddr4 %u daddr4 %u\n", xf->l34m.saddr4, xf->l34m.daddr4);
  //   debug_printf("tc_egress dp_do_nat nxip4 %u nxport %u\n", xf->nm.nxip4, ntohs(xf->nm.nxport));
  //   debug_printf("tc_egress dp_do_nat nrip4 %u nrport %u\n", xf->nm.nrip4, ntohs(xf->nm.nrport));
  //   debug_printf("tc_egress dp_do_nat sport %u dport %u\n", ntohs(xf->l34m.source), ntohs(xf->l34m.dest));
  // }

  return 1;
}

#endif