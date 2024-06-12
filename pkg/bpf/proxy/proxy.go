package proxy

import (
	"fmt"
	"net"

	"github.com/cybwan/f4gw/pkg/bpf"
	"github.com/cybwan/f4gw/pkg/libbpf"
)

func (proxy *F4Proxy) Init() {
	if err := libbpf.RemoveMemlock(); err != nil {
		log.Fatal().Msgf("remove memlock error: %v", err)
	}

	proxy.prog = "proxy"
	proxy.progFile = fmt.Sprintf("%s.kern.o", proxy.prog)

	proxy.cleanCallbacks = make(map[string]func() error)

	if !libbpf.IsBpfFS(bpf.BPF_FS) {
		success, err := libbpf.MountBpfFS(bpf.BPF_FS)
		if err != nil {
			log.Fatal().Err(err).Msg(`mount bpf file system`)
		}
		if !success {
			log.Fatal().Msg(`mount bpf file system error`)
		}
	}

	if err := libbpf.UnloadAll(bpf.BPF_FS, proxy.prog); err != nil {
		log.Fatal().Err(err).Msg(`unloading bpf objects`)
	}

	if err := libbpf.LoadAll(bpf.BPF_FS, proxy.prog, proxy.progFile); err != nil {
		log.Fatal().Err(err).Msg(`loading bpf objects`)
	}

	proxy.cleanCallbacks[`clean bpf Objects`] = func() error {
		libbpf.UnloadAll(bpf.BPF_FS, proxy.prog)
		return nil
	}
}

func (proxy *F4Proxy) Close() {
	for msg, cb := range proxy.cleanCallbacks {
		log.Info().Msg(msg)
		if err := cb(); err != nil {
			log.Error().Err(err)
		}
	}
}

func (proxy *F4Proxy) AttachIngressBPF(iface string) {
	// Look up the network interface by name.
	ingressIface, ingressErr := net.InterfaceByName(iface)
	if ingressErr != nil {
		log.Error().Msgf("lookup network ingress iface %s: %s", iface, ingressErr)
		return
	}

	ingressErr = libbpf.AttachXDP(iface, fmt.Sprintf("%s/%s/%s", bpf.BPF_FS, proxy.prog, "xdp_ingress"))
	if ingressErr != nil {
		log.Fatal().Msgf("could not attach XDP program: %s", ingressErr)
		return
	}

	proxy.cleanCallbacks[fmt.Sprintf("Detached XDP program to ingress iface %q (index %d)", ingressIface.Name, ingressIface.Index)] = func() error {
		libbpf.DetachXDP(iface)
		return nil
	}

	log.Info().Msgf("Attached XDP program to ingress iface %q (index %d)", ingressIface.Name, ingressIface.Index)
}
