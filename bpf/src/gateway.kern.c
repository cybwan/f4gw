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
#include "bpf-compose.h"

char __LICENSE[] SEC("license") = "GPL";

SEC("classifier/ingress")
int tc_ingress(struct __sk_buff *ctx) {
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

  

  // if ( xf->pm.igr == 1 && \
  //   xf->l2m.dl_type == ntohs(ETH_P_IP) && \
  //   xf->l34m.nw_proto == IPPROTO_TCP && \
  //   xf->l34m.saddr4 == 367175872 && \
  //   xf->l34m.daddr4 == 3305231619 && \
  //   xf->l34m.dest == htons(80) ) {
  //   dp_set_tcp_dst_ip(ctx, xf, 551725248);
  // }

  // if ( xf->pm.igr == 1 && \
  //   xf->l2m.dl_type == ntohs(ETH_P_IP) && \
  //   xf->l34m.nw_proto == IPPROTO_TCP && \
  //   xf->l34m.saddr4 == 367175872 && \
  //   xf->l34m.daddr4 == 3305231619 && \
  //   xf->l34m.dest == htons(80) ) {
  //   debug_printf("\n");
  //   debug_printf("\n");
  //   debug_printf("---------------------------------------\n");
  //   debug_printf("tc_ingress saddr4 %u daddr4 %u\n", xf->l34m.saddr4, xf->l34m.daddr4);
  // }

  return dp_ing_fc_main(ctx, xf);
}

SEC("classifier/egress")
int tc_egress(struct __sk_buff *ctx) {
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

  // if ( xf->pm.egr == 1 && \
  //   xf->l2m.dl_type == ntohs(ETH_P_IP) && \
  //   xf->l34m.nw_proto == IPPROTO_TCP && \
  //   xf->l34m.saddr4 == 551725248 && \
  //   xf->l34m.daddr4 == 367175872 && \
  //   xf->l34m.source == htons(8689) ) {
  //   dp_set_tcp_src_ip(ctx, xf, 3305231619);
  //   dp_set_tcp_sport(ctx, xf, htons(80));
  // }

  // if ( xf->pm.egr == 1 && \
  //   xf->l2m.dl_type == ntohs(ETH_P_IP) && \
  //   xf->l34m.nw_proto == IPPROTO_TCP && \
  //   xf->l34m.saddr4 == 551725248 && \
  //   xf->l34m.daddr4 == 367175872 && \
  //   xf->l34m.source == htons(8689) ) {
  //   debug_printf("\n");
  //   debug_printf("\n");
  //   debug_printf("---------------------------------------\n");
  //   debug_printf("tc_egress saddr4 %u daddr4 %u\n", xf->l34m.saddr4, xf->l34m.daddr4);
  // }

  return dp_ing_fc_main(ctx, xf);
  // return DP_PASS;
}

SEC("classifier/slow")
int tc_packet_slow_func(struct __sk_buff *ctx) {
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

SEC("classifier/ct")
int tc_conn_track_func(struct __sk_buff *ctx) {
  int z = 0;
  struct xfrm *xf;

  xf = bpf_map_lookup_elem(&f4gw_xfrms, &z);
  if (!xf) {
    return DP_DROP;
  }

  // if ( xf->pm.egr == 1 && \
  //   xf->l2m.dl_type == ntohs(ETH_P_IP) && \
  //   xf->l34m.nw_proto == IPPROTO_TCP && \
  //   xf->l34m.saddr4 == 551725248 && \
  //   xf->l34m.daddr4 == 367175872 && \
  //   xf->l34m.source == htons(8689) ) {
  //   debug_printf("tc_egress tc_conn_track_func saddr4 %u daddr4 %u\n", xf->l34m.saddr4, xf->l34m.daddr4);
  // }

  return dp_ing_ct_main(ctx, xf);
}

SEC("classifier/pass")
int tc_pass(struct __sk_buff *ctx) {
  return DP_PASS;
}

SEC("classifier/drop")
int tc_drop(struct __sk_buff *ctx) {
  return DP_DROP;
}