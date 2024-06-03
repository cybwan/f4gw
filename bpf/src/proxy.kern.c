#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "bpf-builtin.h"
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

  if (xf->pm.f4) {
    struct dp_nat_opt_key okey;
    struct dp_nat_opt_tact oact;

    memset(&okey, 0, sizeof(okey));
    memset(&oact, 0, sizeof(oact));

    okey.v6 = 0;
    okey.l4proto = xf->f4m.l4proto;
    okey.xaddr = ntohl(xf->f4m.xaddr4);
    okey.xport = ntohs(xf->f4m.xport);

    oact.daddr = ntohl(xf->f4m.daddr4);
    oact.saddr = ntohl(xf->f4m.saddr4);
    oact.dport = ntohs(xf->f4m.dport);
    oact.sport = ntohs(xf->f4m.sport);


    bpf_map_update_elem(&f4gw_nat_opts, &okey, &oact, BPF_ANY);
    
    debug_printf("==================================\n");
    debug_printf("f4m proto %d \t ipv6(?) %d\n", okey.l4proto, okey.v6);
    debug_printf("f4m daddr %pI4 dport %d\n", &oact.daddr, ntohs(oact.dport));
    debug_printf("f4m saddr %pI4 sport %d\n", &oact.saddr, ntohs(oact.sport));
    debug_printf("f4m xaddr %pI4 xport %d\n", &okey.xaddr, ntohs(okey.xport));
  }

  return DP_PASS;
}