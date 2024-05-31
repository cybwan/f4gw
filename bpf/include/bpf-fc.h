#ifndef __F4_BPF_FC_H__ 
#define __F4_BPF_FC_H__

#include "bpf-dbg.h"

static int  __always_inline
dp_mk_fcv4_key(struct xfrm *xf, struct dp_fcv4_key *key)
{
  key->daddr      = xf->l34m.daddr4;
  key->saddr      = xf->l34m.saddr4;
  key->sport      = xf->l34m.source;
  key->dport      = xf->l34m.dest;
  key->l4proto    = xf->l34m.nw_proto;
  key->pad        = 0;
  key->in_port    = 0;
  return 0;
}

static int __always_inline
dp_do_fcv4_lkup(void *ctx, struct xfrm *xf)
{
  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_do_fcv4_lkup\n");
  }

  struct dp_fcv4_key key;
  struct dp_fc_tacts *acts;
  struct dp_fc_tact *ta;
  int ret = 1;
  int z = 0;

  dp_mk_fcv4_key(xf, &key);

  if((F4_DEBUG_INT(xf)) || (F4_DEBUG_EXT(xf))) {
    F4_DBG_FCH4("[FCH4] -- Lookup\n");
    F4_DBG_FCH4("[FCH4] dp_do_fcv4_lkup key-sz %d\n", sizeof(key));
    F4_DBG_FCH4("[FCH4] dp_do_fcv4_lkup saddr %pI4\n", &key.saddr);
    F4_DBG_FCH4("[FCH4] dp_do_fcv4_lkup daddr %pI4\n", &key.daddr);
    F4_DBG_FCH4("[FCH4] dp_do_fcv4_lkup sport %d\n", ntohs(key.sport));
    F4_DBG_FCH4("[FCH4] dp_do_fcv4_lkup dport %d\n", ntohs(key.dport));
    F4_DBG_FCH4("[FCH4] dp_do_fcv4_lkup l4proto %x\n", key.l4proto);
  }

  acts = bpf_map_lookup_elem(&f4gw_fc_v4, &key);
  if (!acts) {
    /* xfck - fcache key table is maintained so that 
     * there is no need to make fcv4 key again in
     * tail-call sections
     */
    if((F4_DEBUG_INT(xf)) || (F4_DEBUG_EXT(xf))) {
      F4_DBG_FCH4("[FCH4] dp_do_fcv4_lkup not found key\n");
      F4_DBG_FCH4("[FCH4] dp_do_fcv4_lkup bpf_map_update_elem xfck\n");
    }
    bpf_map_update_elem(&f4gw_xfck, &z, &key, BPF_ANY);
    return 0; 
  }

  if((F4_DEBUG_INT(xf)) || (F4_DEBUG_EXT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_do_fcv4_lkup found key\n");
  }

  /* Check timeout */ 
  if (bpf_ktime_get_ns() - acts->its > FC_V4_DPTO) {
    if((F4_DEBUG_INT(xf)) || (F4_DEBUG_EXT(xf))) {
      F4_DBG_FCH4("[FCH4] dp_do_fcv4_lkup hto\n");
    }
    bpf_map_update_elem(&f4gw_xfck, &z, &key, BPF_ANY);
    bpf_map_delete_elem(&f4gw_fc_v4, &key);
    xf->pm.rcode |= F4_PIPE_RC_FCTO;
    return 0; 
  }
  
  if((F4_DEBUG_INT(xf)) || (F4_DEBUG_EXT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_do_fcv4_lkup key found act-sz %d\n", sizeof(struct dp_fc_tacts));
  }

  if (acts->ca.ftrap) {
    xf->pm.rcode |= F4_PIPE_RC_FCBP;
    return 0; 
  }

  xf->pm.phit |= F4_DP_FC_HIT;
  xf->pm.zone = acts->zone;
  xf->pm.pten = acts->pten;

  if (acts->fcta[DP_SET_SNAT].ca.act_type == DP_SET_SNAT) {
    if((F4_DEBUG_INT(xf)) || (F4_DEBUG_EXT(xf))) {
      F4_DBG_FCH4("[FCH4] dp_do_fcv4_lkup snat-act\n");
    }
    ta = &acts->fcta[DP_SET_SNAT];

    if (ta->nat_act.fr == 1 || ta->nat_act.doct) {
      xf->pm.rcode |= F4_PIPE_RC_FCBP;
      return 0;
    }

    dp_pipe_set_nat(ctx, xf, &ta->nat_act, 1);
  } else if (acts->fcta[DP_SET_DNAT].ca.act_type == DP_SET_DNAT) {
    if((F4_DEBUG_INT(xf)) || (F4_DEBUG_EXT(xf))) {
      F4_DBG_FCH4("[FCH4] dp_do_fcv4_lkup dnat-act\n");
    }
    ta = &acts->fcta[DP_SET_DNAT];

    if (ta->nat_act.fr == 1 || ta->nat_act.doct) {
      xf->pm.rcode |= F4_PIPE_RC_FCBP;
      return 0;
    }

    dp_pipe_set_nat(ctx, xf, &ta->nat_act, 0);
  }


  /* Catch any conditions which need us to go to cp/ct */
  if (xf->pm.l4fin) {
    acts->ca.ftrap = 1;
    goto del_out;
  }

  // DP_RUN_CT_HELPER(xf);

  if((F4_DEBUG_INT(xf)) || (F4_DEBUG_EXT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_do_fcv4_lkup oport %d\n",  xf->nm.nxifi);
  }

  DP_XMAC_CP(xf->l2m.dl_src, xf->nm.nxmac);
  DP_XMAC_CP(xf->l2m.dl_dst, xf->nm.nrmac);
  xf->pm.oport = xf->nm.nxifi;
  if(F4_DEBUG_INT(xf)) {
    F4_DBG_FCH4("[FCH4] local dp_do_fcv4_lkup oport %d", xf->pm.oport);
    F4_DBG_FCH4("[FCH4] local dp_do_fcv4_lkup SNAT %pI4 %d\n", &xf->nm.nxip4, ntohs(xf->nm.nxport));
    F4_DBG_FCH4("[FCH4] local dp_do_fcv4_lkup dl_src %02x:%02x:%02x", xf->l2m.dl_src[0],xf->l2m.dl_src[1],xf->l2m.dl_src[2]);
    F4_DBG_FCH4("[FCH4] local dp_do_fcv4_lkup dl_src %02x:%02x:%02x", xf->l2m.dl_src[3],xf->l2m.dl_src[4],xf->l2m.dl_src[5]);
    F4_DBG_FCH4("[FCH4] local dp_do_fcv4_lkup dl_dst %02x:%02x:%02x", xf->l2m.dl_dst[0],xf->l2m.dl_dst[1],xf->l2m.dl_dst[2]);
    F4_DBG_FCH4("[FCH4] local dp_do_fcv4_lkup dl_dst %02x:%02x:%02x", xf->l2m.dl_dst[3],xf->l2m.dl_dst[4],xf->l2m.dl_dst[5]);
  }
  if(F4_DEBUG_EXT(xf)) {
    F4_DBG_FCH4("[FCH4] remote dp_do_fcv4_lkup oport %d", xf->pm.oport);
    F4_DBG_FCH4("[FCH4] remote dp_do_fcv4_lkup DNAT %pI4 %d\n", &xf->nm.nrip4, ntohs(xf->nm.nxport));
    F4_DBG_FCH4("[FCH4] remote dp_do_fcv4_lkup dl_src %02x:%02x:%02x", xf->l2m.dl_src[0],xf->l2m.dl_src[1],xf->l2m.dl_src[2]);
    F4_DBG_FCH4("[FCH4] remote dp_do_fcv4_lkup dl_src %02x:%02x:%02x", xf->l2m.dl_src[3],xf->l2m.dl_src[4],xf->l2m.dl_src[5]);
    F4_DBG_FCH4("[FCH4] remote dp_do_fcv4_lkup dl_dst %02x:%02x:%02x", xf->l2m.dl_dst[0],xf->l2m.dl_dst[1],xf->l2m.dl_dst[2]);
    F4_DBG_FCH4("[FCH4] remote dp_do_fcv4_lkup dl_dst %02x:%02x:%02x", xf->l2m.dl_dst[3],xf->l2m.dl_dst[4],xf->l2m.dl_dst[5]);
  }
  
  dp_unparse_packet_always(ctx, xf);
  dp_unparse_packet(ctx, xf);

  F4_PPLN_RDR(xf);

  return ret;

del_out:
  bpf_map_delete_elem(&f4gw_fc_v4, &key);
  xf->pm.rcode |= F4_PIPE_RC_FCBP;
  return 0;
}

static int __always_inline
dp_ing_fc_main(void *ctx, struct xfrm *xf)
{
  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_ing_fc_main ========\n");
  }

  int z = 0;
  int oif;
  if (xf->pm.pipe_act == 0 &&
      xf->l2m.dl_type == ntohs(ETH_P_IP)) {
    if (dp_do_fcv4_lkup(ctx, xf) == 1) {
      if (xf->pm.pipe_act == F4_PIPE_RDR) {
        oif = xf->pm.oport;
        return bpf_redirect(oif, 0);         
      }
    }
  }

  bpf_map_update_elem(&f4gw_xfrms, &z, xf, BPF_ANY);
  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_ing_fc_main bpf_tail_call F4_DP_PKT_SLOW_PGM_ID\n");
  }
  bpf_tail_call(ctx, &f4gw_progs, F4_DP_PKT_SLOW_PGM_ID);
  return DP_DROP;
}

#endif