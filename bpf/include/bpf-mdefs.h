#ifndef __F4_BPF_MDEFS_H__ 
#define __F4_BPF_MDEFS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") f4gw_progs = {
  .type = BPF_MAP_TYPE_PROG_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u32),
  .max_entries = F4_PGM_MAP_ENTRIES,
  //.pinning = 1,
};
#else /* New BTF definitions */
struct {
  __uint(type,        BPF_MAP_TYPE_PROG_ARRAY);
  __type(key,         __u32);
  __type(value,       __u32);
  __uint(max_entries, F4_PGM_MAP_ENTRIES);
  __uint(pinning,     1);
} f4gw_progs SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") f4gw_xfrms = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct xfrm),
  .max_entries = 1,
};
#else /* New BTF definitions */
struct {
  __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key,         __u32);
  __type(value,       struct xfrm);
  __uint(max_entries, 1);
} f4gw_xfrms SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") f4gw_xfck = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct dp_fcv4_key),
  .max_entries = 1,
};
#else /* New BTF definitions */
struct {
  __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key,         __u32);
  __type(value,       struct dp_fcv4_key);
  __uint(max_entries, 1);
} f4gw_xfck SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") f4gw_fcas = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct dp_fc_tacts),
  .max_entries = 1,
};
#else /* New BTF definitions */
struct {
  __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key,         __u32);
  __type(value,       struct dp_fc_tacts);
  __uint(max_entries, 1);
} f4gw_fcas SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") f4gw_fc_v4 = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct dp_fcv4_key),
  .value_size = sizeof(struct dp_fc_tacts),
  .max_entries = F4_FCV4_MAP_ENTRIES,
  .map_flags = BPF_F_NO_PREALLOC,
  //.pinning = 1,
};
#else /* New BTF definitions */
struct {
  __uint(type,        BPF_MAP_TYPE_HASH);
  __type(key,         struct dp_fcv4_key);
  __type(value,       struct dp_fc_tacts);
  __uint(max_entries, F4_FCV4_MAP_ENTRIES);
  __uint(map_flags,   BPF_F_NO_PREALLOC);
  // __uint(pinning,     1);
} f4gw_fc_v4 SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") f4gw_nat = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct dp_nat_key),
  .value_size = sizeof(struct dp_nat_tacts),
  .max_entries = F4_NATV4_MAP_ENTRIES,
  //.pinning = 1,
};
#else /* New BTF definitions */
struct {
  __uint(type,        BPF_MAP_TYPE_HASH);
  __type(key,         struct dp_nat_key);
  __type(value,       struct dp_nat_tacts);
  __uint(max_entries, F4_NATV4_MAP_ENTRIES);
  __uint(pinning,     1);
} f4gw_nat SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") f4gw_nat_ep = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct dp_nat_epacts),
  .max_entries = F4_NAT_EP_MAP_ENTRIES,
};
#else /* New BTF definitions */
struct {
  __uint(type,        BPF_MAP_TYPE_ARRAY);
  __type(key,         __u32);
  __type(value,       struct dp_nat_epacts);
  __uint(max_entries, F4_NAT_EP_MAP_ENTRIES);
} f4gw_nat_ep SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") f4gw_xctk = {
  .type = BPF_MAP_TYPE_PERCPU_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct dp_ct_tact),
  .max_entries = 1,
};
#else /* New BTF definitions */
struct {
  __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key,         __u32);
  __type(value,       struct dp_ct_tact);
  __uint(max_entries, 2);
} f4gw_xctk SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") f4gw_ct_ctr = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct dp_ct_ctrtact),
  .max_entries = 1,
};
#else /* New BTF definitions */
struct {
  __uint(type,        BPF_MAP_TYPE_ARRAY);
  __type(key,         __u32);
  __type(value,       struct dp_ct_ctrtact);
  __uint(max_entries, 1);
} f4gw_ct_ctr SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") f4gw_ct = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct dp_ct_key),
  .value_size = sizeof(struct dp_ct_tact),
  .max_entries = F4_CT_MAP_ENTRIES,
};
#else /* New BTF definitions */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __type(key,         struct dp_ct_key);
    __type(value,       struct dp_ct_tact);
    __uint(max_entries, F4_CT_MAP_ENTRIES);
} f4gw_ct SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") f4gw_igr_ipv4 = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u8),
  .max_entries = F4_MAX_IFI_ADDRS,
  //.pinning = 1,
};
#else /* New BTF definitions */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __type(key,         __u32);
    __type(value,       __u8);
    __uint(max_entries, F4_MAX_IFI_ADDRS);
    __uint(pinning,     1);
} f4gw_igr_ipv4 SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") f4gw_egr_ipv4 = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u8),
  .max_entries = F4_MAX_IFI_ADDRS,
  //.pinning = 1,
};
#else /* New BTF definitions */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __type(key,         __u32);
    __type(value,       __u8);
    __uint(max_entries, F4_MAX_IFI_ADDRS);
    __uint(pinning,     1);
} f4gw_egr_ipv4 SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct bpf_map_def SEC("maps") f4gw_nat_opts = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(struct dp_nat_opt_key),
  .value_size = sizeof(struct dp_nat_opt_tact),
  .max_entries = F4_FCV4_MAP_ENTRIES,
  .map_flags = BPF_F_NO_PREALLOC,
  //.pinning = 1,
};
#else /* New BTF definitions */
struct {
  __uint(type,        BPF_MAP_TYPE_HASH);
  __type(key,         struct dp_nat_opt_key);
  __type(value,       struct dp_nat_opt_tact);
  __uint(max_entries, F4_FCV4_MAP_ENTRIES);
  __uint(map_flags,   BPF_F_NO_PREALLOC);
  __uint(pinning,     1);
} f4gw_nat_opts SEC(".maps");
#endif
#endif