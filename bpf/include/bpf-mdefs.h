#ifndef __F4_BPF_MDEFS_H__ 
#define __F4_BPF_MDEFS_H__

#define __uint(name, val)  int (*name)[val]
#define __type(name, val)  typeof(val) *name
#define __array(name, val) typeof(val) *name[]

struct {
  __uint(type,        BPF_MAP_TYPE_PROG_ARRAY);
  __type(key,         __u32);
  __type(value,       __u32);
  __uint(max_entries, F4_PGM_MAP_ENTRIES);
  __uint(pinning,     1);
} f4gw_progs SEC(".maps");

struct {
  __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key,         __u32);
  __type(value,       struct xfrm);
  __uint(max_entries, 1);
} f4gw_xfrms SEC(".maps");

struct {
  __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key,         __u32);
  __type(value,       struct dp_fcv4_key);
  __uint(max_entries, 1);
} f4gw_xfck SEC(".maps");

struct {
  __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key,         __u32);
  __type(value,       struct dp_fc_tacts);
  __uint(max_entries, 1);
} f4gw_fcas SEC(".maps");

struct {
  __uint(type,        BPF_MAP_TYPE_HASH);
  __type(key,         struct dp_fcv4_key);
  __type(value,       struct dp_fc_tacts);
  __uint(max_entries, F4_FCV4_MAP_ENTRIES);
  __uint(map_flags,   BPF_F_NO_PREALLOC);
  __uint(pinning,     1);
} f4gw_fc_v4 SEC(".maps");

struct {
  __uint(type,        BPF_MAP_TYPE_HASH);
  __type(key,         struct dp_nat_key);
  __type(value,       struct dp_nat_tacts);
  __uint(max_entries, F4_NATV4_MAP_ENTRIES);
  __uint(pinning,     1);
} f4gw_nat SEC(".maps");

struct {
  __uint(type,        BPF_MAP_TYPE_ARRAY);
  __type(key,         __u32);
  __type(value,       struct dp_nat_epacts);
  __uint(max_entries, F4_NAT_EP_MAP_ENTRIES);
} f4gw_nat_ep SEC(".maps");

struct {
  __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key,         __u32);
  __type(value,       struct dp_ct_tact);
  __uint(max_entries, 2);
} f4gw_xctk SEC(".maps");

struct {
  __uint(type,        BPF_MAP_TYPE_ARRAY);
  __type(key,         __u32);
  __type(value,       struct dp_ct_ctrtact);
  __uint(max_entries, 1);
} f4gw_ct_ctr SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __type(key,         struct dp_ct_key);
    __type(value,       struct dp_ct_tact);
    __uint(max_entries, F4_CT_MAP_ENTRIES);
} f4gw_ct SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __type(key,         __u32);
    __type(value,       __u8);
    __uint(max_entries, F4_MAX_IFI_ADDRS);
    __uint(pinning,     1);
} f4gw_igr_ipv4 SEC(".maps");

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __type(key,         __u32);
    __type(value,       __u8);
    __uint(max_entries, F4_MAX_IFI_ADDRS);
    __uint(pinning,     1);
} f4gw_egr_ipv4 SEC(".maps");

struct {
  __uint(type,        BPF_MAP_TYPE_HASH);
  __type(key,         struct dp_nat_opt_key);
  __type(value,       struct dp_nat_opt_tact);
  __uint(max_entries, F4_FCV4_MAP_ENTRIES);
  __uint(map_flags,   BPF_F_NO_PREALLOC);
  __uint(pinning,     1);
} f4gw_nat_opts SEC(".maps");
#endif