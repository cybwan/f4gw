package proxy

import (
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/cybwan/f4gw/pkg/bpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags $BPF_CFLAGS bpf $BPF_SRC_DIR/proxy.kern.c -- -I $BPF_INC_DIR

func (proxy *F4Proxy) Init() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Error().Msgf("remove memlock error: %v", err)
		return err
	}

	proxy.cleanCallbacks = make(map[string]func() error)
	proxy.bpfObjs = new(bpfObjects)

	opts := ebpf.CollectionOptions{}
	opts.Maps.PinPath = bpf.BPF_FS
	if err := loadBpfObjects(proxy.bpfObjs, &opts); err != nil {
		log.Error().Err(err).Msg(`loading bpf objects`)
		return err
	}

	proxy.cleanCallbacks[`close bpf Objects`] = proxy.bpfObjs.Close
	proxy.cleanCallbacks[`clean bpf Maps`] = func() error {
		os.Remove(fmt.Sprintf(`%s/%s`, bpf.BPF_FS, `f4gw_nat_opts`))
		os.Remove(fmt.Sprintf(`%s/%s`, bpf.BPF_FS, `f4gw_egr_ipv4`))
		os.Remove(fmt.Sprintf(`%s/%s`, bpf.BPF_FS, `f4gw_igr_ipv4`))
		os.Remove(fmt.Sprintf(`%s/%s`, bpf.BPF_FS, `f4gw_fc_v4`))
		os.Remove(fmt.Sprintf(`%s/%s`, bpf.BPF_FS, `f4gw_nat`))
		os.Remove(fmt.Sprintf(`%s/%s`, bpf.BPF_FS, `f4gw_progs`))
		return nil
	}

	return nil
}

func (proxy *F4Proxy) Close() {
	for msg, cb := range proxy.cleanCallbacks {
		log.Info().Msg(msg)
		if err := cb(); err != nil {
			log.Error().Err(err)
		}
	}
}

func (proxy *F4Proxy) AttachIngressBPF(iface string) error {
	// Look up the network interface by name.
	ingressIface, ingressErr := net.InterfaceByName(iface)
	if ingressErr != nil {
		log.Error().Msgf("lookup network ingress iface %s: %s", iface, ingressErr)
		return ingressErr
	}
	// Attach the program.
	ingressLink, attachErr := link.AttachXDP(link.XDPOptions{
		Program:   proxy.bpfObjs.XdpIngress,
		Interface: ingressIface.Index,
	})
	if ingressErr != nil {
		log.Error().Msgf("could not attach XDP program: %s", attachErr)
		return attachErr
	}

	proxy.cleanCallbacks[fmt.Sprintf("Detached XDP program to ingress iface %q (index %d)", ingressIface.Name, ingressIface.Index)] = ingressLink.Close

	log.Info().Msgf("Attached XDP program to ingress iface %q (index %d)", ingressIface.Name, ingressIface.Index)

	return nil
}
