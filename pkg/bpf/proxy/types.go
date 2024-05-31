package proxy

import "github.com/cybwan/l4gw/pkg/logger"

var (
	log = logger.New("flomesh-f4proxy")
)

type F4Proxy struct {
	bpfObjs *bpfObjects

	cleanCallbacks map[string]func() error
}

type F4ProxyIngress struct {
	LinkName string `json:"linkName"`
}

type F4ProxyConfig struct {
	WorkDuration string           `json:"workDuration"`
	Ingress      []F4ProxyIngress `json:"ingress"`
}
