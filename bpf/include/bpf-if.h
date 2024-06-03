#ifndef __F4_BPF_DEVIF_H__ 
#define __F4_BPF_DEVIF_H__

#include "bpf-dbg.h"
#include "bpf-compose.h"
#include "bpf-l2.h"
#include "bpf-lb.h"
#include "bpf-f4.h"

static int __always_inline
dp_redir_packet(void *ctx,  struct xfrm *xf)
{
  return DP_REDIRECT;
}

static int __always_inline
dp_f4_packet(void *ctx,  struct xfrm *xf)
{
  struct ethhdr *neth;
  struct f4hdr *f4hdr;
  void *dend;

  if (dp_add_l2(ctx, (int)sizeof(*f4hdr))) {
    /* This can fail to push headroom for tunnelled packets.
     * It might be better to pass it rather than drop it in case
     * of failure
     */
    return -1;
  }

  neth = DP_TC_PTR(DP_PDATA(ctx));
  dend = DP_TC_PTR(DP_PDATA_END(ctx));
  if (neth + 1 > dend) {
    return -1;
  }

  DP_XMAC_CP(neth->h_dest, xf->l2m.dl_dst);
  DP_XMAC_CP(neth->h_source, xf->l2m.dl_src);
  neth->h_proto = htons(ETH_P_F4); 
  
  f4hdr = DP_ADD_PTR(neth, sizeof(*neth));
  if (f4hdr + 1 > dend) {
    return -1;
  }

  f4hdr->l4proto = xf->f4m.l4proto;
  f4hdr->daddr = xf->f4m.daddr4;
  f4hdr->saddr = xf->f4m.saddr4;
  f4hdr->xaddr = xf->f4m.xaddr4;
  f4hdr->dport = xf->f4m.dport;
  f4hdr->sport = xf->f4m.sport;
  f4hdr->xport = xf->f4m.xport;

  return 0;
}

static int __always_inline
dp_insert_fcv4(void *ctx, struct xfrm *xf, struct dp_fc_tacts *acts)
{
  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_FCH4("\n");
    F4_DBG_FCH4("[FCH4] dp_insert_fcv4 ========\n");
  }
  struct dp_fcv4_key *key;
  int z = 0;

  int oif = xf->nm.nxifi;
  if (oif) {
    acts->ca.oaux = oif;
  } 

  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_insert_fcv4 NS--\n");
    F4_DBG_FCH4("[FCH4] dp_insert_fcv4 oif=%d\n", oif);
  }

  key = bpf_map_lookup_elem(&f4gw_xfck, &z);
  if (key == NULL) {
    if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
      F4_DBG_FCH4("[FCH4] dp_insert_fcv4 xfck key miss\n");
    }
    return -1;
  }

  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_insert_fcv4 xfck key hit\n");
  }

  if (bpf_map_lookup_elem(&f4gw_fc_v4, key) != NULL) {
    if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
      F4_DBG_FCH4("[FCH4] dp_insert_fcv4 fc_v4_map key hit\n");
    }
    return 1;
  }

  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_insert_fcv4 fc_v4_map key miss\n");
  }
  
  acts->pten = xf->pm.pten;
  bpf_map_update_elem(&f4gw_fc_v4, key, acts, BPF_ANY);
  return 0;
}

static int __always_inline
dp_pipe_check_res(void *ctx, struct xfrm *xf, void *fa)
{
  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_IF("[CKRS] xf->pm.pipe_act %d xf->pm.nf %d", xf->pm.pipe_act, xf->pm.nf);
  }

  if(xf->l34m.nw_proto == IPPROTO_TCP) {
    F4_DBG_FCH4("[FCH4] dp_pipe_check_res ========\n");
    F4_DBG_FCH4("[FCH4] dp_pipe_check_res xf->pm.pipe_act %d\n", xf->pm.pipe_act);
  }

  if (xf->pm.pipe_act) {

    if (xf->pm.pipe_act & F4_PIPE_DROP) {
      return DP_DROP;
    }

    if (xf->pm.pipe_act & F4_PIPE_RDR) {
      DP_XMAC_CP(xf->l2m.dl_src, xf->nm.nxmac);
      DP_XMAC_CP(xf->l2m.dl_dst, xf->nm.nrmac);
      xf->pm.oport = xf->nm.nxifi;
      if(F4_DEBUG_INT(xf)) {
        F4_DBG_IF("[CKRS] local dp_pipe_check_res oport %d", xf->pm.oport);
        F4_DBG_IF("[CKRS] local SNAT %pI4 %d\n", &xf->nm.nxip4, ntohs(xf->nm.nxport));
        F4_DBG_IF("[CKRS] local dp_pipe_check_res dl_src %02x:%02x:%02x", xf->l2m.dl_src[0],xf->l2m.dl_src[1],xf->l2m.dl_src[2]);
        F4_DBG_IF("[CKRS] local dp_pipe_check_res dl_src %02x:%02x:%02x", xf->l2m.dl_src[3],xf->l2m.dl_src[4],xf->l2m.dl_src[5]);
        F4_DBG_IF("[CKRS] local dp_pipe_check_res dl_dst %02x:%02x:%02x", xf->l2m.dl_dst[0],xf->l2m.dl_dst[1],xf->l2m.dl_dst[2]);
        F4_DBG_IF("[CKRS] local dp_pipe_check_res dl_dst %02x:%02x:%02x", xf->l2m.dl_dst[3],xf->l2m.dl_dst[4],xf->l2m.dl_dst[5]);
      }
      if(F4_DEBUG_EXT(xf)) {
        F4_DBG_IF("[CKRS] remote dp_pipe_check_res oport %d", xf->pm.oport);
        F4_DBG_IF("[CKRS] remote DNAT %pI4 %d\n", &xf->nm.nrip4, ntohs(xf->nm.nxport));
        F4_DBG_IF("[CKRS] remote dp_pipe_check_res dl_src %02x:%02x:%02x", xf->l2m.dl_src[0],xf->l2m.dl_src[1],xf->l2m.dl_src[2]);
        F4_DBG_IF("[CKRS] remote dp_pipe_check_res dl_src %02x:%02x:%02x", xf->l2m.dl_src[3],xf->l2m.dl_src[4],xf->l2m.dl_src[5]);
        F4_DBG_IF("[CKRS] remote dp_pipe_check_res dl_dst %02x:%02x:%02x", xf->l2m.dl_dst[0],xf->l2m.dl_dst[1],xf->l2m.dl_dst[2]);
        F4_DBG_IF("[CKRS] remote dp_pipe_check_res dl_dst %02x:%02x:%02x", xf->l2m.dl_dst[3],xf->l2m.dl_dst[4],xf->l2m.dl_dst[5]);
      }
    }

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

    if (dp_unparse_packet_always(ctx, xf) != 0) {
        return DP_DROP;
    }

    if (xf->pm.pipe_act & F4_PIPE_RDR_MASK) {
      if (dp_unparse_packet(ctx, xf) != 0) {
        return DP_DROP;
      }
      if (xf->pm.f4) {
        if (dp_f4_packet(ctx, xf) != 0) {
          return DP_DROP;
        }
      }
      return bpf_redirect(xf->pm.oport, 0);
    }

  }
  return DP_PASS; /* FIXME */
}

static int __always_inline 
dp_ing_ct_main(void *ctx,  struct xfrm *xf)
{
  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_ing_ct_main\n");
  }
  int val = 0;
  struct dp_fc_tacts *fa = NULL;

  fa = bpf_map_lookup_elem(&f4gw_fcas, &val);
  if (!fa) return DP_DROP;

  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_IF("[CTM] src addr=%pI4\n", &xf->l34m.saddr4);
    F4_DBG_IF("[CTM] dst addr=%pI4\n", &xf->l34m.daddr4);
    F4_DBG_IF("[CTM] src port=%d\n", ntohs(xf->l34m.source));
    F4_DBG_IF("[CTM] dst port=%d\n", ntohs(xf->l34m.dest));

    F4_DBG_FCH4("[FCH4] dp_ing_ct_main src addr=%pI4\n", &xf->l34m.saddr4);
    F4_DBG_FCH4("[FCH4] dp_ing_ct_main dst addr=%pI4\n", &xf->l34m.daddr4);
    F4_DBG_FCH4("[FCH4] dp_ing_ct_main src port=%d\n", ntohs(xf->l34m.source));
    F4_DBG_FCH4("[FCH4] dp_ing_ct_main dst port=%d\n", ntohs(xf->l34m.dest));
  }

  if (xf->pm.phit & F4_DP_RES_HIT) {
    if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
      F4_DBG_IF("[CTM] res_end\n");
      F4_DBG_FCH4("[FCH4] dp_ing_ct_main res_end\n");
    }
    goto res_end;
  }

  if (xf->pm.igr && (xf->pm.phit & F4_DP_CTM_HIT) == 0) {
    if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
      F4_DBG_FCH4("[FCH4] dp_ing_ct_main go dp_do_nat\n");
    }
    dp_do_nat(ctx, xf);
    if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
      F4_DBG_IF("[CTM] dp_do_nat DONE pipe_act %d\n", xf->pm.pipe_act);
    }
  }

  val = dp_ct_in(ctx, xf);
  if (val < 0) {
    if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
      F4_DBG_FCH4("[FCH4] smr %d\n", val);
    }
    return DP_PASS;
  }

  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_ing_ct_main go dp_l3_fwd\n");
  }
  dp_l3_fwd(ctx, xf, fa);

  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_ing_ct_main go dp_eg_l2\n");
  }
  dp_eg_l2(ctx, xf, fa);

res_end:
  if (1) {
    if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
      F4_DBG_FCH4("[FCH4] dp_ing_ct_main go dp_pipe_check_res\n");
    }
    int ret = dp_pipe_check_res(ctx, xf, fa);
    if (ret == DP_DROP) {
      F4_DBG_IF("[CTM] Drop RC 0x%x", xf->pm.rcode);
    }
    return ret;
  }
}

static int __always_inline
dp_ing_slow_main(void *ctx,  struct xfrm *xf)
{
  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_ing_slow_main ========\n");
  }
  struct dp_fc_tacts *fa = NULL;
  int z = 0;

  fa = bpf_map_lookup_elem(&f4gw_fcas, &z);
  if (!fa) return 0;

  /* No nonsense no loop */
  fa->ca.ftrap = 0;
  fa->ca.cidx = 0;
  fa->zone = 0;
  fa->its = bpf_ktime_get_ns();
#pragma clang loop unroll(full)
  for (z = 0; z < F4_FCV4_MAP_ACTS; z++) {
    fa->fcta[z].ca.act_type = 0;
  }

  // F4_DBG_PRINTK("[INGR] START--\n");

  // /* If there are any packets marked for mirroring, we do
  //  * it here and immediately get it out of way without
  //  * doing any further processing
  //  */
  // if (xf->pm.mirr != 0) {
  //   dp_do_mirr_lkup(ctx, xf);
  //   goto out;
  // }

  // dp_ing(ctx, xf);

  /* If there are pipeline errors at this stage,
   * we again skip any further processing
   */
  if (xf->pm.pipe_act || xf->pm.tc == 0) {
    if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
      F4_DBG_FCH4("[FCH4] dp_ing_slow_main go out ( skip dp_insert_fcv4 ?)\n");
    }
    goto out;
  }

  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_ing_slow_main go dp_ing_l2 ( skip dp_insert_fcv4 ?)\n");
  }
  dp_ing_l2(ctx, xf, fa);

  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_ing_slow_main pm.pipe_act F4_PIPE_RDR %d\n", xf->pm.pipe_act & F4_PIPE_RDR);
    F4_DBG_FCH4("[FCH4] dp_ing_slow_main pm.phit   F4_DP_CTM_HIT %d\n", xf->pm.phit & F4_DP_CTM_HIT);
  }

  /* fast-cache is used only when certain conditions are met */
  if (F4_PIPE_FC_CAP(xf)) {
    fa->zone = xf->pm.zone;
    if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
      F4_DBG_FCH4("[FCH4] dp_ing_slow_main go dp_insert_fcv4\n");
    }
    dp_insert_fcv4(ctx, xf, fa);
  }

out:
  xf->pm.phit |= F4_DP_RES_HIT;

  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_IF("[SLM] dp_ing_slow_main set xf->pm.phit F4_DP_RES_HIT\n");
  }

  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_ing_slow_main bpf_tail_call F4_DP_CT_PGM_ID\n");
  }
  bpf_tail_call(ctx, &f4gw_progs, F4_DP_CT_PGM_ID);
  return DP_PASS;
}

#endif