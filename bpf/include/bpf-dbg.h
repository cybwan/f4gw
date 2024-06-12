#ifndef __F4_BPF_DEBUG_H__ 
#define __F4_BPF_DEBUG_H__

#ifdef F4_DP_DEBUG 
#define F4_DBG_PRINTK debug_printf
#else
#define F4_DBG_PRINTK(fmt, ...)  do { } while (0) 
#endif

#ifdef F4_DP_DEBUG_IF
#define F4_DBG_IF debug_printf
#else
#define F4_DBG_IF(fmt, ...)  do { } while (0) 
#endif

#ifdef F4_DP_DEBUG_FCH4
#define F4_DBG_FCH4 debug_printf
#else
#define F4_DBG_FCH4(fmt, ...)  do { } while (0) 
#endif

#ifdef F4_DP_DEBUG_NTLB
#define F4_DBG_NTLB debug_printf
#else
#define F4_DBG_NTLB(fmt, ...)  do { } while (0) 
#endif

// #define F4_DEBUG_INT(x) 0
// #define F4_DEBUG_EXT(x) 0

#define F4_DEBUG_INT(x) \
  ( x->pm.igr == 1 && \
  x->l2m.dl_type == ntohs(ETH_P_IP) && \
  x->l34m.nw_proto == IPPROTO_TCP && \
  x->l34m.saddr4 == 367175872 && \
  x->l34m.daddr4 == 1894764562 && \
  x->l34m.dest == htons(80) )

#define F4_DEBUG_EXT(x) \
  ( x->pm.egr == 1 && \
  x->l2m.dl_type == ntohs(ETH_P_IP) && \
  x->l34m.nw_proto == IPPROTO_TCP && \
  x->l34m.saddr4 == 528459968 && \
  x->l34m.daddr4 == 545237184 && \
  x->l34m.source == htons(80) )

#define F4_DEBUG_PKT(x) (F4_DEBUG_INT(x) || F4_DEBUG_EXT(x))

#ifdef F4_DP_DEBUG_CTRK
#define F4_DBG_CTRK debug_printf
#else
#define F4_DBG_CTRK(fmt, ...)  do { } while (0) 
#endif

#endif