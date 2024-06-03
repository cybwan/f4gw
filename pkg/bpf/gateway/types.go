package gateway

import "github.com/cybwan/f4gw/pkg/logger"

const (
	FLM_DP_PKT_SLOW_PGM_ID = int32(1)
	FLM_DP_CT_PGM_ID       = int32(2)
	FLM_DP_PASS_PGM_ID     = int32(3)
	FLM_DP_DROP_PGM_ID     = int32(4)
)

const (
	DP_SET_SNAT NatActionType = 1
	DP_SET_DNAT NatActionType = 2
)

type NatActionType uint8

const (
	NAT_LB_SEL_RR         LbSelector = 0
	NAT_LB_SEL_HASH       LbSelector = 1
	NAT_LB_SEL_PRIO       LbSelector = 2
	NAT_LB_SEL_RR_PERSIST LbSelector = 3
	NAT_LB_SEL_LC         LbSelector = 4
)

type LbSelector uint16

const (
	IPPROTO_ICMP L4Proto = 1
	IPPROTO_TCP  L4Proto = 6
	IPPROTO_UDP  L4Proto = 17
)

type L4Proto uint8

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
	TargetProto L4Proto       `json:"targetProto"`
	TargetAddr  string        `json:"targetAddr"`
	TargetPort  uint16        `json:"targetPort"`
	ViaLinkName string        `json:"viaLinkName"`
	ViaLinkAddr string        `json:"viaLinkAddr"`
	Backends    []F4GwBackend `json:"backends"`
}

type F4GwConfig struct {
	WorkDuration string        `json:"workDuration"`
	Ingress      []F4GwIngress `json:"ingress"`
	Egress       []F4GwEgress  `json:"egress"`
}
