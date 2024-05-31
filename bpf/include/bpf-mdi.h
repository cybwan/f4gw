#ifndef __F4_BPF_MDI_H__ 
#define __F4_BPF_MDI_H__

#define F4_PIPE_FC_CAP(x)                     \
  ((x)->pm.pipe_act & F4_PIPE_RDR &&         \
  (x)->pm.phit & F4_DP_CTM_HIT &&            \
  !((x)->pm.phit & F4_DP_SESS_HIT) &&        \
  (x)->l2m.dl_type == htons(ETH_P_IP) &&  \
  (x)->nm.xlate_proto == 0 &&                 \
  (x)->pm.dp_rec == 0 &&                      \
  (x)->l2m.ssnid == 0 &&                      \
  (x)->pm.mirr == 0)

#define F4_PIPE_RDR_MASK     (F4_PIPE_RDR | F4_PIPE_RDR_PRIO | F4_PIPE_TRAP)

struct dp_pi_mdi {
    /* Pipeline Metadata */
    __u16            bd;
    __u16            py_bytes;
#define F4_PIPE_TRAP         0x1
#define F4_PIPE_DROP         0x2
#define F4_PIPE_RDR          0x4
#define F4_PIPE_PASS         0x8
#define F4_PIPE_REWIRE       0x10
#define F4_PIPE_RDR_PRIO     0x20
#define F4_PIPE_SET_CT       0x40
#define F4_PIPE_F4M          0x80
    __u8             pipe_act;
    __u8             l3_off;
#define F4_DP_TMAC_HIT       0x1
#define F4_DP_CTM_HIT        0x2
#define F4_DP_IF_HIT         0x4
#define F4_DP_RT_HIT         0x8
#define F4_DP_FC_HIT         0x10
#define F4_DP_SESS_HIT       0x20
#define F4_DP_RES_HIT        0x40
#define F4_DP_FW_HIT         0x80
#define F4_DP_CTSI_HIT       0x100
#define F4_DP_CTSO_HIT       0x200
#define F4_DP_NAT_HIT        0x400
#define F4_DP_CSUM_HIT       0x800
#define F4_DP_UNPS_HIT       0x1000
#define F4_DP_NEIGH_HIT      0x2000
#define F4_DP_SMAC_HIT       0x4000
#define F4_DP_DMAC_HIT       0x8000
    __u16            phit;

    __u16            nh_num;
    __u16            qos_id;
#define F4_PIPE_RC_PARSER    0x1
#define F4_PIPE_RC_ACL_TRAP  0x2
#define F4_PIPE_RC_TUN_DECAP 0x4
#define F4_PIPE_RC_FW_RDR    0x8
#define F4_PIPE_RC_FW_DRP    0x10
#define F4_PIPE_RC_UNPS_DRP  0x20
#define F4_PIPE_RC_UNX_DRP   0x40
#define F4_PIPE_RC_MPT_PASS  0x80
#define F4_PIPE_RC_FCTO      0x100
#define F4_PIPE_RC_FCBP      0x200
#define F4_PIPE_RC_PLERR     0x400
#define F4_PIPE_RC_PROTO_ERR 0x800
#define F4_PIPE_RC_PLCT_ERR  0x1000
#define F4_PIPE_RC_ACT_DROP  0x2000
#define F4_PIPE_RC_ACT_UNK   0x4000
#define F4_PIPE_RC_TCALL_ERR 0x8000
#define F4_PIPE_RC_ACT_TRAP  0x10000
#define F4_PIPE_RC_PLRT_ERR  0x20000
#define F4_PIPE_RC_PLCS_ERR  0x40000
#define F4_PIPE_RC_BCMC      0x80000
#define F4_PIPE_RC_POL_DRP   0x100000
#define F4_PIPE_RC_NOSMAC    0x200000
#define F4_PIPE_RC_NODMAC    0x400000
#define F4_PIPE_RC_RT_TRAP   0x800000
#define F4_PIPE_RC_CSUM_DRP  0x1000000
#define F4_PIPE_RC_NH_UNK    0x2000000
#define F4_PIPE_RC_RESOLVE   0x4000000
    __u32            rcode;

    __u32            ifi;
    __u8             igr:2;
    __u8             egr:2;
    __u8             f4:2;
    __u8             tc;
#define LLB_DP_PORT_UPP       0x1
    __u8             pprop;
    __u8             lkup_dmac[6];
    __u16            iport;
    __u16            oport;
    __u16            zone;
    __u8             l4_off;
    __u8             table_id;

    __u64            sseid;
    __u64            dseid;

#define F4_MIRR_MARK         0xdeadbeef
    __u16            mirr;
#define F4_TCP_FIN           0x01
#define F4_TCP_SYN           0x02
#define F4_TCP_RST           0x04
#define F4_TCP_PSH           0x08
#define F4_TCP_ACK           0x10
#define F4_TCP_URG           0x20
    __u8             tcp_flags;
#define F4_NAT_DST           0x01
#define F4_NAT_SRC           0x02
#define F4_NAT_HDST          0x04
#define F4_NAT_HSRC          0x08
    __u8             nf;
    __u16            rule_id;
    __s16            l3_adj;

    __u8             il3_off;
    __u8             il4_off;
    __u8             itcp_flags;
    __u8             l4fin:1;
    __u8             dbg:1;
    __u8             goct:1;
    __u8             nfc:1;
    __u8             pten:2;
    __u8             il4fin:1;
    __u8             dir:1;
    __u16            l3_len;
    __u16            l3_plen;
    __u16            il3_len;
    __u16            il3_plen;
    __u16            dp_mark;
    __u16            dp_rec;
    __u16            tun_off;
    __u16            fw_mid;
    __u16            fw_lid;
    __u16            fw_rid;
}__attribute__((packed));


struct dp_fr_mdi {
    __u32            dat;
    __u32            dat_end;
    __u64            tstamp;
};

/* Allow users of header file to redefine VLAN max depth */
#ifndef MAX_STACKED_VLANS
#define MAX_STACKED_VLANS 3
#endif

struct dp_l2_mdi {
    __u16            vlan[MAX_STACKED_VLANS]; 
    __u16            dl_type;
    __u8             dl_dst[6];
    __u8             dl_src[6];
    __u8             vlan_pcp;
    __u8             valid;
    __u16            ssnid;
};

#define saddr4 saddr[0]
#define daddr4 daddr[0]
#define xaddr4 xaddr[0]

struct dp_f4_mdi {
    __u8            l4proto;

    __u16            sport;
    __u16            dport;
    __u16            xport;

    __u32            saddr[4];
    __u32            daddr[4];
    __u32            xaddr[4];
};

struct dp_l34_mdi {
    __u8             tos;
    __u8             nw_proto;

    __u8             valid;
    __u8             frg;

    __u16            source;
    __u16            dest;

    __u32            seq;
    __u32            ack;

    __u32            saddr[4];
    __u32            daddr[4];
};

#define nxip4 nxip[0]
#define nrip4 nrip[0]

struct dp_nat_mdi {
    __u32            nxip[4];      /* NAT xIP */
    __u32            nrip[4];      /* NAT rIP (for one-arm) */
    __u16            nxport;       /* NAT xport */
    __u16            nrport;       /* NAT rport */
    __u16            nxifi;
    __u8             nxmac[6];
    __u8             nrmac[6];
#define F4_PIPE_CT_NONE  0
#define F4_PIPE_CT_INP   1
#define F4_PIPE_CT_EST   2
    __u8            ct_sts;        /* Conntrack state */
    __u8            sel_aid;
    __u8            nv6;
    __u8            xlate_proto;
    __u8            dsr;
    __u8            cdis;
    __u64           ito;
};

struct xfrm {
    struct dp_fr_mdi  fm;
    struct dp_l2_mdi  l2m;
    struct dp_l34_mdi l34m;
    struct dp_l2_mdi  il2m;
    struct dp_l34_mdi il34m;
    struct dp_nat_mdi nm;
    struct dp_f4_mdi  f4m;

    /* Pipeline Info*/
    struct dp_pi_mdi  pm;
}__attribute__((packed));

#define ETH_TYPE_ETH2(x) ((x) >= htons(1536))

typedef enum {
  DP_PRET_FAIL  = -1,
  DP_PRET_OK    =  0,
  DP_PRET_TRAP  =  1,
  DP_PRET_PASS  =  2
}dpret_t;

/* Parser to help ebpf packet parsing */
struct parser {
  __u8 in_pkt:1;
  __u8 skip_l2:1;
  __u8 skip_v6:1;
  __u8 res:5;
  void *start;
  void *dbegin;
  void *dend;
};

#define VLAN_VID_MASK  0x0fff
#define VLAN_PCP_MASK  0xe000
#define VLAN_PCP_SHIFT 13

/* Allow users of header file to redefine VLAN max depth */
#ifndef MAX_STACKED_VLANS
#define MAX_STACKED_VLANS 3
#endif

/*
 *	struct vlanhdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlanhdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

/*
 *	struct arp_ethhdr - arp header
 *	@ar_hrd: Hardware type
 *	@ar_pro: Protocol type
 *	@ar_hln: Protocol address len
 *	@ar_op:  ARP opcode
 *	@ar_sha: Sender hardware/mac address
 *	@ar_spa: Sender protocol address
 *	@ar_tha: Target hardware/mac address
 *	@ar_tpa: Target protocol address
 */
struct arp_ethhdr {
  __be16    ar_hrd;
  __be16    ar_pro;
  __u8      ar_hln;
  __u8      ar_pln;
  __be16    ar_op;
  __u8      ar_sha[6];
  __be32    ar_spa;
  __u8      ar_tha[6];
  __be32    ar_tpa;
} __attribute__((packed));

#endif