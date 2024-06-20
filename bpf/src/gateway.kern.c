#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "bpf-utils.h"
#include "bpf-config.h"
#include "bpf-dp.h"
#include "bpf-mdi.h"
#include "bpf-mdefs.h"
#include "bpf-cdefs.h"
#include "bpf-if.h"
#include "bpf-l2.h"
#include "bpf-l3.h"
#include "bpf-fc.h"
#include "bpf-lb.h"
#include "bpf-ct.h"
#include "bpf-f4.h"
#include "bpf-compose.h"

char __LICENSE[] SEC("license") = "GPL";

SEC("xdp/ingress")
int xdp_ingress(struct xdp_md *ctx) {
  int z = 0;
  struct xfrm *xf;

  xf = bpf_map_lookup_elem(&f4gw_xfrms, &z);
  if (!xf) {
    return DP_DROP;
  }
  memset(xf, 0, sizeof *xf);

  xf->pm.igr = 1;
  xf->pm.ifi = ctx->ingress_ifindex;

  dp_parse_d0(ctx, xf, 1);

  return dp_ing_fc_main(ctx, xf);
}

SEC("xdp/egress")
int xdp_egress(struct xdp_md *ctx) {
  int z = 0;
  struct xfrm *xf;

  xf = bpf_map_lookup_elem(&f4gw_xfrms, &z);
  if (!xf) {
    return DP_DROP;
  }
  memset(xf, 0, sizeof *xf);

  xf->pm.egr = 1;
  xf->pm.ifi = ctx->ingress_ifindex;

  dp_parse_d0(ctx, xf, 1);

  return dp_ing_fc_main(ctx, xf);
}

SEC("xdp/slow_func")
int xdp_packet_slow_func(struct xdp_md *ctx) {
  int z = 0;
  struct xfrm *xf;

  xf = bpf_map_lookup_elem(&f4gw_xfrms, &z);
  if (!xf) {
    return DP_DROP;
  }

  xf->pm.phit |= F4_DP_FC_HIT;
  xf->pm.tc = 1;

  if (xf->pm.pipe_act & F4_PIPE_PASS ||
      xf->pm.pipe_act & F4_PIPE_TRAP) {
    xf->pm.rcode |= F4_PIPE_RC_MPT_PASS;
    return DP_PASS;
  }

  return dp_ing_slow_main(ctx, xf);
}

SEC("xdp/ct_func")
int xdp_conn_track_func(struct xdp_md *ctx) {
  int z = 0;
  struct xfrm *xf;

  xf = bpf_map_lookup_elem(&f4gw_xfrms, &z);
  if (!xf) {
    return DP_DROP;
  }

  return dp_ing_ct_main(ctx, xf);
}

SEC("xdp/pass")
int xdp_pass(struct xdp_md *ctx) {
  return DP_PASS;
}

SEC("xdp/drop")
int xdp_drop(struct xdp_md *ctx) {
  return DP_DROP;
}