#ifndef __F4_BPF_F4_H__ 
#define __F4_BPF_F4_H__

/* F4 header type */
#define ETH_P_F4 0x8689

struct f4hdr {
  __u8  l4proto;
  __u32 saddr;
  __u32 daddr;
  __u32 xaddr;
  __u16 sport;
  __u16 dport;
  __u16 xport;
} __attribute__((packed));

#endif