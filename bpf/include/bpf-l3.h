#ifndef __F4_BPF_L3_H__ 
#define __F4_BPF_L3_H__

#include "bpf-dbg.h"
#include "bpf-ct.h"
#include "bpf-lb.h"

static int __always_inline
dp_do_ctops(void *ctx, struct xfrm *xf, void *fa_, 
             struct dp_ct_tact *act)
{
  if ((F4_DEBUG_INT(xf)) || (F4_DEBUG_EXT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_do_ctops");
  }
  struct dp_fc_tacts *fa = fa_;
  if (!act) {
    if ((F4_DEBUG_INT(xf)) || (F4_DEBUG_EXT(xf))) {
      F4_DBG_CTRK("[CTRK] dp_do_ctops miss");
      F4_DBG_FCH4("[FCH4] dp_do_ctops miss\n");
    }
    goto ct_trk;
  }

  xf->pm.phit |= F4_DP_CTM_HIT;
  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_CTRK("[CTRK] dp_do_ctops set xf->pm.phit F4_DP_CTM_HIT\n");
  }

  act->lts = bpf_ktime_get_ns();

  fa->ca.cidx = act->ca.cidx;
  fa->ca.fwrid = act->ca.fwrid;

  if ((F4_DEBUG_INT(xf)) || (F4_DEBUG_EXT(xf))) {
    F4_DBG_CTRK("[CTRK] dp_do_ctops act_type=%d", act->ca.act_type);
    F4_DBG_FCH4("[FCH4] dp_do_ctops act_type=%d", act->ca.act_type);
  }

  if (act->ca.act_type == DP_SET_DO_CT) {
    goto ct_trk;
  } else if (act->ca.act_type == DP_SET_NOP) {
    struct dp_rdr_act *ar = &act->port_act;
    if (xf->pm.l4fin) {
      ar->fr = 1;
    }

    if (ar->fr == 1) {
      goto ct_trk;
    }

  } else if (act->ca.act_type == DP_SET_RDR_PORT) {
    struct dp_rdr_act *ar = &act->port_act;
    if ((F4_DEBUG_INT(xf)) || (F4_DEBUG_EXT(xf))) {
      F4_DBG_CTRK("[CTRK] dp_do_ctops DP_SET_RDR_PORT\n");
    }
    if (xf->pm.l4fin) {
      ar->fr = 1;
    }

    if (ar->fr == 1) {
      goto ct_trk;
    }

    F4_PPLN_RDR_PRIO(xf);
    xf->pm.oport = ar->oport;
  } else if (act->ca.act_type == DP_SET_SNAT || 
             act->ca.act_type == DP_SET_DNAT) {
    struct dp_nat_act *na;
    struct dp_fc_tact *ta = &fa->fcta[
                                  act->ca.act_type == DP_SET_SNAT ?
                                  DP_SET_SNAT : DP_SET_DNAT];
    ta->ca.act_type = act->ca.act_type;
    memcpy(&ta->nat_act,  &act->nat_act, sizeof(act->nat_act));

    na = &act->nat_act;

    if (xf->pm.l4fin) {
      na->fr = 1;
    }

    if ((F4_DEBUG_INT(xf)) || (F4_DEBUG_EXT(xf))) {
      F4_DBG_CTRK("[CTRK] dp_do_ctops xipv4=%pI4\n", &na->xip[0]);
      F4_DBG_CTRK("[CTRK] dp_do_ctops ripv4=%pI4\n", &na->rip[0]);

      F4_DBG_FCH4("[FCH4] dp_do_ctops xipv4=%pI4\n", &na->xip[0]);
      F4_DBG_FCH4("[FCH4] dp_do_ctops ripv4=%pI4\n", &na->rip[0]);
    }

    dp_pipe_set_nat(ctx, xf, na, act->ca.act_type == DP_SET_SNAT ? 1: 0);

    if (na->fr == 1 || na->doct || xf->pm.goct) {
      if ((F4_DEBUG_INT(xf)) || (F4_DEBUG_EXT(xf))) {
        F4_DBG_FCH4("[FCH4] dp_do_ctops goto ct_trk na->fr=%d na->doct=%d xf->pm.goct=%d\n", na->fr, na->doct, xf->pm.goct);
      }
      goto ct_trk;
    }

    F4_PPLN_RDR(xf);
  } else if (act->ca.act_type == DP_SET_TOCP) {
    F4_PPLN_PASSC(xf, F4_PIPE_RC_ACL_TRAP);
  } else {
    /* Same for DP_SET_DROP */
    F4_PPLN_DROPC(xf, F4_PIPE_RC_ACT_DROP);
  }

  if (xf->l34m.nw_proto == IPPROTO_TCP) {
    dp_run_ctact_helper(xf, act);
  }

  return 0;

ct_trk:
if ((F4_DEBUG_INT(xf)) || (F4_DEBUG_EXT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_do_ctops dp_tail_call F4_DP_CT_PGM_ID");
  }
  return dp_tail_call(ctx, xf, fa_, F4_DP_CT_PGM_ID);
}

static int __always_inline
dp_do_ing_ct(void *ctx, struct xfrm *xf, void *fa_)
{
  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_do_ing_ct\n");
  }

  struct dp_ct_key key;
  struct dp_ct_tact *act;

  CT_KEY_GEN(&key, xf);

  // if ((F4_DEBUG_INT(xf)) || (F4_DEBUG_EXT(xf))) {
  //   F4_DBG_CTRK("[CTRK] dp_do_ing_ct Lookup");
  //   F4_DBG_CTRK("[CTRK] dp_do_ing_ct saddr %pI4", &key.saddr[0]);
  //   F4_DBG_CTRK("[CTRK] dp_do_ing_ct daddr %pI4", &key.daddr[0]);
  //   F4_DBG_CTRK("[CTRK] dp_do_ing_ct sport %d", ntohs(key.sport));
  //   F4_DBG_CTRK("[CTRK] dp_do_ing_ct dport %d", ntohs(key.dport));
  //   F4_DBG_CTRK("[CTRK] dp_do_ing_ct proto %d", key.l4proto);
  // }
  
  if ((F4_DEBUG_INT(xf)) || (F4_DEBUG_EXT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_do_ing_ct Lookup");
  }

  // xf->pm.table_id = F4_DP_CT_MAP;
  act = bpf_map_lookup_elem(&f4gw_ct, &key);
  if (!act) {
    if ((F4_DEBUG_INT(xf)) || (F4_DEBUG_EXT(xf))) {
      F4_DBG_CTRK("[CTRK] dp_do_ing_ct miss");
      F4_DBG_FCH4("[FCH4] dp_do_ing_ct miss\n");
    }
  } else {
    if ((F4_DEBUG_INT(xf)) || (F4_DEBUG_EXT(xf))) {
      F4_DBG_CTRK("[CTRK] dp_do_ing_ct hit");
      F4_DBG_FCH4("[FCH4] dp_do_ing_ct hit");
    }
  }

  return dp_do_ctops(ctx, xf, fa_, act);
}

static int __always_inline
dp_l3_fwd(void *ctx,  struct xfrm *xf, void *fa)
{
  if (xf->l2m.dl_type == htons(ETH_P_IP)) {
    if (xf->pm.nf && xf->nm.nv6 != 0) {
      xf->nm.xlate_proto = 1;
      // dp_do_ipv6_fwd(ctx, xf, fa);
    } else {
      // dp_do_ipv4_fwd(ctx, xf, fa);
    }
  } else if (xf->l2m.dl_type == htons(ETH_P_IPV6)) {
    if (xf->pm.nf && xf->nm.nv6 == 0) {
      xf->nm.xlate_proto = 1;
      // dp_do_ipv4_fwd(ctx, xf, fa);
    } else {
      // dp_do_ipv6_fwd(ctx, xf, fa);
    }
  }
  return 0;
}

static int __always_inline
dp_ing_l3(void *ctx,  struct xfrm *xf, void *fa)
{

  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_ing_l3\n");
  }
  dp_do_ing_ct(ctx, xf, fa);
  // dp_l3_fwd(ctx, xf, fa);

  return 0;
}

#endif