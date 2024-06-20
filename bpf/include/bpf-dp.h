#ifndef __F4_BPF_DP_H__ 
#define __F4_BPF_DP_H__

enum {
  DP_SET_DROP            = 0,
  DP_SET_SNAT            = 1,
  DP_SET_DNAT            = 2,
  DP_SET_NEIGH_L2        = 3,
  DP_SET_ADD_L2VLAN      = 4,
  DP_SET_RM_L2VLAN       = 5,
  DP_SET_TOCP            = 6,
  DP_SET_RM_VXLAN        = 7,
  DP_SET_NEIGH_VXLAN     = 8,
  DP_SET_RT_TUN_NH       = 9,
  DP_SET_L3RT_TUN_NH     = 10,
  DP_SET_IFI             = 11,
  DP_SET_NOP             = 12,
  DP_SET_L3_EN           = 13,
  DP_SET_RT_NHNUM        = 14,
  DP_SET_SESS_FWD_ACT    = 15,
  DP_SET_RDR_PORT        = 16,
  DP_SET_POLICER         = 17,
  DP_SET_DO_POLICER      = 18,
  DP_SET_FCACT           = 19,
  DP_SET_DO_CT           = 20,
  DP_SET_RM_GTP          = 21,
  DP_SET_ADD_GTP         = 22,
  DP_SET_NEIGH_IPIP      = 23,
  DP_SET_RM_IPIP         = 24,
  DP_SET_NACT_SESS       = 25
};

/* Connection tracking related defines */
typedef enum {
  CT_DIR_IN = 0,
  CT_DIR_OUT,
  CT_DIR_MAX
} ct_dir_t;

typedef enum {
  CT_STATE_NONE = 0x0,
  CT_STATE_REQ  = 0x1,
  CT_STATE_REP  = 0x2,
  CT_STATE_EST  = 0x4,
  CT_STATE_FIN  = 0x8,
  CT_STATE_DOR  = 0x10
} ct_state_t;

typedef enum {
  CT_SMR_ERR    = -1,
  CT_SMR_INPROG = 0,
  CT_SMR_EST    = 1,
  CT_SMR_UEST   = 2,
  CT_SMR_FIN    = 3,
  CT_SMR_CTD    = 4,
  CT_SMR_UNT    = 100,
  CT_SMR_INIT   = 200,
} ct_smr_t;

struct dp_cmn_act {
  __u8 act_type;
  __u8 ftrap;
  __u16 oaux;
  __u32 cidx;
  __u32 fwrid;
  __u16 mark;
  __u16 record;
};

#define CT_TCP_FIN_MASK (CT_TCP_FINI|CT_TCP_FINI2|CT_TCP_FINI3|CT_TCP_CW)
#define CT_TCP_SYNC_MASK (CT_TCP_SS|CT_TCP_SA)

typedef enum {
  CT_TCP_CLOSED = 0x0,
  CT_TCP_SS     = 0x1,
  CT_TCP_SA     = 0x2,
  CT_TCP_EST    = 0x4,
  CT_TCP_FINI   = 0x10,
  CT_TCP_FINI2  = 0x20,
  CT_TCP_FINI3  = 0x40,
  CT_TCP_CW     = 0x80,
  CT_TCP_ERR    = 0x100
} ct_tcp_state_t;

typedef struct {
  __u16 hstate;
#define CT_TCP_INIT_ACK_THRESHOLD 3
  __u16 init_acks;
  __u32 seq;
  __be32 pack;
  __be32 pseq;
} ct_tcp_pinfd_t;

typedef struct {
  ct_tcp_state_t state;
  ct_dir_t fndir;
  ct_tcp_pinfd_t tcp_cts[CT_DIR_MAX];
} ct_tcp_pinf_t;

#define CT_UDP_FIN_MASK (CT_UDP_FINI)

typedef enum {
  CT_UDP_CNI    = 0x0,
  CT_UDP_UEST   = 0x1,
  CT_UDP_EST    = 0x2,
  CT_UDP_FINI   = 0x8,
  CT_UDP_CW     = 0x10,
} ct_udp_state_t;

typedef struct {
  __u16 state;
#define CT_UDP_CONN_THRESHOLD 4
  __u16 pkts_seen;
  __u16 rpkts_seen;
   ct_dir_t fndir;
} ct_udp_pinf_t;

typedef enum {
  CT_ICMP_CLOSED= 0x0,
  CT_ICMP_REQS  = 0x1,
  CT_ICMP_REPS  = 0x2,
  CT_ICMP_FINI  = 0x4,
  CT_ICMP_DUNR  = 0x8,
  CT_ICMP_TTL   = 0x10,
  CT_ICMP_RDR   = 0x20,
  CT_ICMP_UNK   = 0x40,
} ct_icmp_state_t;

typedef struct {
  __u8  state;
  __u8  errs;
  __u16 lseq;
} ct_icmp_pinf_t;

typedef struct {
  ct_state_t state;
} ct_l3inf_t;

typedef struct {
  union {
    ct_tcp_pinf_t t;
    ct_udp_pinf_t u;
    ct_icmp_pinf_t i;
  };
  __u16 frag;
  __u16 npmhh;
  __u32 pmhh[4];
  ct_l3inf_t l3i;
} ct_pinf_t;

struct dp_rdr_act {
  __u16 oport;
  __u16 fr;
};

#define nat_xip4 nat_xip[0]
#define nat_rip4 nat_rip[0]

struct dp_xfrm_inf
{
  /* F4_NAT_XXX flags */
  __u8 nat_flags;
  __u8 inactive;
  __u8 wprio;
  __u8 nv6;
  __u8 dsr;
  __u8 _padding;
  __u16 nat_xifi;
  __u16 nat_xport;
  __u16 nat_rport;
  __u32 nat_xip[4];
  __u32 nat_rip[4];
  __u8  nat_xmac[6];
  __u8  nat_rmac[6];
  __u16 osp; // original src port
  __u16 odp; // original dst port
};
typedef struct dp_xfrm_inf nxfrm_inf_t;

struct dp_pb_stats {
  __u64 bytes;
  __u64 packets;
};
typedef struct dp_pb_stats dp_pb_stats_t;

struct dp_ct_dat {
  __u16 rid;
  __u16 aid;
  __u32 nid;
  ct_pinf_t pi;
  ct_dir_t dir;
  ct_smr_t smr;
  nxfrm_inf_t xi;
  dp_pb_stats_t pb;
};

struct dp_fcv4_key {
  __u32 daddr; 
  __u32 saddr; 
  __u16 sport; 
  __u16 dport; 
  __u8  l4proto;
  __u8  pad;
  __u16 in_port;
};

struct dp_nat_act {
  __u32 xip[4];
  __u32 rip[4];
  __u16 xport;
  __u16 rport;
  __u16 xifi;
  __u8  xmac[6];
  __u8  rmac[6];
  __u8 fr;
  __u8 doct;
  __u32 rid;
  __u32 aid;
  __u8 nv6;
  __u8 dsr;
  __u8 cdis;
  __u8 nmh;
};

struct dp_fc_tact {
  struct dp_cmn_act ca; /* Possible actions : See below */
  union {
    struct dp_rdr_act port_act;
    struct dp_nat_act nat_act;           /* DP_SET_SNAT, DP_SET_DNAT */
  };
};

struct dp_fc_tacts {
  struct dp_cmn_act ca;
  __u64 its;
  __u32 zone;
  __u16 pad;
  __u16 pten;
  struct dp_fc_tact fcta[F4_FCV4_MAP_ACTS];
};

struct dp_nat_key {
  __u32 daddr[4];
  __u16 dport;
  __u16 zone;
  __u16 mark;
  __u8  l4proto;
  __u8  v6;
};

#define NAT_LB_SEL_RR   0
#define NAT_LB_SEL_HASH 1
#define NAT_LB_SEL_PRIO 2
#define NAT_LB_SEL_RR_PERSIST 3
#define NAT_LB_SEL_LC 4

#define NAT_LB_PERSIST_TIMEOUT (10800000000000ULL)

struct dp_nat_tacts {
  struct dp_cmn_act ca;
  __u64 ito;
  __u64 pto;
  struct bpf_spin_lock lock;
  __u8 cdis;
  __u16 sel_hint;
  __u16 sel_type;
  __u16 nxfrm;
  struct dp_xfrm_inf nxfrms[F4_MAX_NXFRMS];
  __u64 lts;
  __u64 base_to;
};

struct dp_nat_epacts {
  struct dp_cmn_act ca;
  struct bpf_spin_lock lock;
  __u32 active_sess[F4_MAX_NXFRMS];
};

struct dp_ct_key {
  __u32 daddr[4];
  __u32 saddr[4];
  __u16 sport;
  __u16 dport;
  __u16 zone;
  __u8  l4proto;
  __u8  v6;
};

struct dp_ct_tact {
  struct dp_cmn_act ca; /* Possible actions :
                         *  DP_SET_DROP
                         *  DP_SET_TOCP
                         *  DP_SET_NOP
                         *  DP_SET_RDR_PORT
                         *  DP_SET_RT_NHNUM
                         *  DP_SET_SESS_FWD_ACT
                         */
  struct bpf_spin_lock lock;
  struct dp_ct_dat ctd;
  __u64 ito;            /* Inactive timeout */
  __u64 lts;            /* Last used timestamp */
  union {
    struct dp_rdr_act port_act;
    struct dp_nat_act nat_act;
  };
};

struct dp_ct_ctrtact {
  struct dp_cmn_act ca; /* Possible actions :
                         * None (just place holder)
                         */
  struct bpf_spin_lock lock;
  __u32 start;
  __u32 counter;
  __u32 entries;
};

struct dp_nat_opt_key {
  __u32 xaddr;
  __u16 xport;
  __u8  l4proto;
  __u8  v6;
};

struct dp_nat_opt_tact {
  __u32 daddr;
  __u32 saddr;
  __u16 sport;
  __u16 dport;
};

struct dp_t4 {
  __be32 saddr;
  __be32 daddr;
  __be16 source;
  __be16 dest;
} __attribute__((aligned(4)));

struct dp_t2_addr {
  __be32 saddr;
  __be32 daddr;
} __attribute__((aligned(4)));

struct dp_t2_port {
  __be16 source;
  __be16 dest;
} __attribute__((aligned(4)));

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define memset(dest, c, n) __builtin_memset((dest), (c), (n))
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER)	((unsigned long)&((TYPE *)0)->MEMBER)
#endif

#define DP_ADD_PTR(x, len) ((void *)(((__u8 *)((long)x)) + (len)))
#define DP_TC_PTR(x) ((void *)((long)x))
#define DP_DIFF_PTR(x, y) (((__u8 *)DP_TC_PTR(x)) - ((__u8 *)DP_TC_PTR(y)))

#define DP_XADDR_ISZR(a) ((a)[0] == 0 && \
                          (a)[1] == 0 && \
                          (a)[2] == 0 && \
                          (a)[3] == 0)

#define DP_XADDR_CP(a, b)        \
do {                             \
  (a)[0] = (b)[0];               \
  (a)[1] = (b)[1];               \
  (a)[2] = (b)[2];               \
  (a)[3] = (b)[3];               \
} while (0)

#define DP_XADDR_SETZR(a)        \
do {                             \
  (a)[0] = 0;                    \
  (a)[1] = 0;                    \
  (a)[2] = 0;                    \
  (a)[3] = 0;                    \
} while(0)


#define DP_XMAC_CP(a, b)         \
do {                             \
  (a)[0] = (b)[0];               \
  (a)[1] = (b)[1];               \
  (a)[2] = (b)[2];               \
  (a)[3] = (b)[3];               \
  (a)[4] = (b)[4];               \
  (a)[5] = (b)[5];               \
} while (0)

#define DP_XMAC_SETZR(a)         \
do {                             \
  (a)[0] = 0;                    \
  (a)[1] = 0;                    \
  (a)[2] = 0;                    \
  (a)[3] = 0;                    \
  (a)[4] = 0;                    \
  (a)[5] = 0;                    \
} while(0)

#endif