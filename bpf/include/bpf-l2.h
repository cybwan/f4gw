#ifndef __F4_BPF_L2_H__ 
#define __F4_BPF_L2_H__

#include "bpf-dbg.h"
#include "bpf-l3.h"

static int __always_inline
dp_eg_l2(void *ctx,  struct xfrm *xf, void *fa)
{
  // /* Any processing based on results from L3 */
  // if (xf->pm.pipe_act & F4_PIPE_RDR_MASK) {
  //   return 0;
  // }   
      
  // if (xf->pm.nh_num != 0) {
  //   dp_do_nh_lkup(ctx, xf, fa);
  // }

  // dp_do_map_stats(ctx, xf, F4_DP_TX_BD_STATS_MAP, xf->pm.bd);

  // dp_do_dmac_lkup(ctx, xf, fa);
  return 0;
}

static int __always_inline
dp_ing_fwd(void *ctx,  struct xfrm *xf, void *fa)
{
  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_ing_fwd\n");
  }
  dp_ing_l3(ctx, xf, fa);
  return dp_eg_l2(ctx, xf, fa);
}

static int __always_inline
dp_ing_l2_top(void *ctx,  struct xfrm *xf, void *fa)
{
  // dp_do_smac_lkup(ctx, xf, fa);
  // dp_do_tmac_lkup(ctx, xf, fa);
  // dp_do_tun_lkup(ctx, xf, fa);
  return 0;
}

static int __always_inline
dp_ing_l2(void *ctx,  struct xfrm *xf, void *fa)
{
  // F4_DBG_PRINTK("[ING L2]");
  // dp_ing_l2_top(ctx, xf, fa);
  if((F4_DEBUG_EXT(xf)) || (F4_DEBUG_INT(xf))) {
    F4_DBG_FCH4("[FCH4] dp_ing_l2\n");
  }
  return dp_ing_fwd(ctx, xf, fa);
}

#endif