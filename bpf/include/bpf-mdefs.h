#ifndef __F4_BPF_MDEFS_H__ 
#define __F4_BPF_MDEFS_H__

#define __uint(name, val)  int (*name)[val]
#define __type(name, val)  typeof(val) *name
#define __array(name, val) typeof(val) *name[]

#ifdef LEGACY_BPF_MAPS
struct {
  int (*type)[BPF_MAP_TYPE_PROG_ARRAY];
  int (*max_entries)[F4_PGM_MAP_ENTRIES];
  __u32 *key;
  __u32 *value;
  int (*pinning)[1];
} f4gw_progs SEC(".maps");
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
struct {
  int (*type)[BPF_MAP_TYPE_PERCPU_ARRAY];
  int (*max_entries)[1];
  __u32 *key;
  struct xfrm *value;
} f4gw_xfrms SEC(".maps");
#else /* New BTF definitions */
struct {
  __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key,         __u32);
  __type(value,       struct xfrm);
  __uint(max_entries, 1);
} f4gw_xfrms SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct {
  int (*type)[BPF_MAP_TYPE_PERCPU_ARRAY];
  int (*max_entries)[1];
  __u32 *key;
  struct dp_fcv4_key *value;
} f4gw_xfck SEC(".maps");
#else /* New BTF definitions */
struct {
  __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key,         __u32);
  __type(value,       struct dp_fcv4_key);
  __uint(max_entries, 1);
} f4gw_xfck SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct {
  int (*type)[BPF_MAP_TYPE_PERCPU_ARRAY];
  int (*max_entries)[1];
  __u32 *key;
  struct dp_fc_tacts *value;
} f4gw_fcas SEC(".maps");
#else /* New BTF definitions */
struct {
  __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key,         __u32);
  __type(value,       struct dp_fc_tacts);
  __uint(max_entries, 1);
} f4gw_fcas SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct {
  int (*type)[BPF_MAP_TYPE_HASH];
  int (*max_entries)[F4_FCV4_MAP_ENTRIES];
  struct dp_fcv4_key *key;
  struct dp_fc_tacts *value;
  int (*map_flags)[BPF_F_NO_PREALLOC];
  int (*pinning)[1];
} f4gw_fc_v4 SEC(".maps");
#else /* New BTF definitions */
struct {
  __uint(type,        BPF_MAP_TYPE_HASH);
  __type(key,         struct dp_fcv4_key);
  __type(value,       struct dp_fc_tacts);
  __uint(max_entries, F4_FCV4_MAP_ENTRIES);
  __uint(map_flags,   BPF_F_NO_PREALLOC);
  __uint(pinning,     1);
} f4gw_fc_v4 SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct {
  int (*type)[BPF_MAP_TYPE_HASH];
  int (*max_entries)[F4_NATV4_MAP_ENTRIES];
  struct dp_nat_key *key;
  struct dp_nat_tacts *value;
  int (*pinning)[1];
} f4gw_nat SEC(".maps");
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
struct {
  int (*type)[BPF_MAP_TYPE_ARRAY];
  int (*max_entries)[F4_NAT_EP_MAP_ENTRIES];
  __u32 *key;
  struct dp_nat_epacts *value;
} f4gw_nat_ep SEC(".maps");
#else /* New BTF definitions */
struct {
  __uint(type,        BPF_MAP_TYPE_ARRAY);
  __type(key,         __u32);
  __type(value,       struct dp_nat_epacts);
  __uint(max_entries, F4_NAT_EP_MAP_ENTRIES);
} f4gw_nat_ep SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct {
  int (*type)[BPF_MAP_TYPE_PERCPU_ARRAY];
  int (*max_entries)[2];
  __u32 *key;
  struct dp_ct_tact *value;
} f4gw_xctk SEC(".maps");
#else /* New BTF definitions */
struct {
  __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key,         __u32);
  __type(value,       struct dp_ct_tact);
  __uint(max_entries, 2);
} f4gw_xctk SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct {
  int (*type)[BPF_MAP_TYPE_ARRAY];
  int (*max_entries)[1];
  __u32 *key;
  struct dp_ct_ctrtact *value;
} f4gw_ct_ctr SEC(".maps");
#else /* New BTF definitions */
struct {
  __uint(type,        BPF_MAP_TYPE_ARRAY);
  __type(key,         __u32);
  __type(value,       struct dp_ct_ctrtact);
  __uint(max_entries, 1);
} f4gw_ct_ctr SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct {
  int (*type)[BPF_MAP_TYPE_HASH];
  int (*max_entries)[F4_CT_MAP_ENTRIES];
  struct dp_ct_key *key;
  struct dp_ct_tact *value;
} f4gw_ct SEC(".maps");
#else /* New BTF definitions */
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __type(key,         struct dp_ct_key);
    __type(value,       struct dp_ct_tact);
    __uint(max_entries, F4_CT_MAP_ENTRIES);
} f4gw_ct SEC(".maps");
#endif

#ifdef LEGACY_BPF_MAPS
struct {
  int (*type)[BPF_MAP_TYPE_HASH];
  int (*max_entries)[F4_MAX_IFI_ADDRS];
  __u32 *key;
  __u8 *value;
  int (*pinning)[1];
} f4gw_igr_ipv4 SEC(".maps");
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
struct {
  int (*type)[BPF_MAP_TYPE_HASH];
  int (*max_entries)[F4_MAX_IFI_ADDRS];
  __u32 *key;
  __u8 *value;
  int (*pinning)[1];
} f4gw_egr_ipv4 SEC(".maps");
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
struct {
  int (*type)[BPF_MAP_TYPE_HASH];
  int (*max_entries)[F4_FCV4_MAP_ENTRIES];
  struct dp_nat_opt_key *key;
  struct dp_nat_opt_tact *value;
  int (*map_flags)[BPF_F_NO_PREALLOC];
  int (*pinning)[1];
} f4gw_nat_opts SEC(".maps");
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