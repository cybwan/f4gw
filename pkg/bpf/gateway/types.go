package gateway

import "github.com/cybwan/l4gw/pkg/logger"

const (
	FLM_DP_PKT_SLOW_PGM_ID = int32(1)
	FLM_DP_CT_PGM_ID       = int32(2)
	FLM_DP_PASS_PGM_ID     = int32(3)
	FLM_DP_DROP_PGM_ID     = int32(4)
)

const (
	DP_SET_SNAT = 1
	DP_SET_DNAT = 2
)

const (
	NAT_LB_SEL_RR         = 0
	NAT_LB_SEL_HASH       = 1
	NAT_LB_SEL_PRIO       = 2
	NAT_LB_SEL_RR_PERSIST = 3
	NAT_LB_SEL_LC         = 4
)

var (
	log = logger.New("flomesh-f4gw")
)

type F4Gw struct {
	bpfObjs *bpfObjects

	cleanCallbacks map[string]func() error
}

type F4GwBackend struct {
	IPv4 string `json:"ipv4"`
	Port uint16 `json:"port"`
}

type F4GwIngress struct {
	LinkName string `json:"linkName"`
}

type F4GwEgress struct {
	ViaName  string        `json:"viaName"`
	ViaAddr  string        `json:"viaAddr"`
	Backends []F4GwBackend `json:"backends"`
}

type F4GwConfig struct {
	WorkDuration string        `json:"workDuration"`
	Ingress      []F4GwIngress `json:"ingress"`
	Egress       []F4GwEgress  `json:"egress"`
}
