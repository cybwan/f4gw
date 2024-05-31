package gateway

import (
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/mdlayher/arp"

	"github.com/cybwan/f4gw/pkg/bpf"
	"github.com/cybwan/f4gw/pkg/netaddr"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags $BPF_CFLAGS bpf $BPF_SRC_DIR/gateway.kern.c -- -I $BPF_INC_DIR

func (gw *F4Gw) Init() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Error().Msgf("remove memlock error: %v", err)
		return err
	}

	gw.cleanCallbacks = make(map[string]func() error)
	gw.bpfObjs = new(bpfObjects)

	opts := ebpf.CollectionOptions{}
	opts.Maps.PinPath = bpf.BPF_FS
	if err := loadBpfObjects(gw.bpfObjs, &opts); err != nil {
		log.Error().Msg(err.Error())
		return err
	}

	gw.cleanCallbacks[`close bpf Objects`] = gw.bpfObjs.Close
	gw.cleanCallbacks[`clean bpf Maps`] = func() error {
		os.Remove(fmt.Sprintf(`%s/%s`, bpf.BPF_FS, `f4gw_nat_opts`))
		os.Remove(fmt.Sprintf(`%s/%s`, bpf.BPF_FS, `f4gw_egr_ipv4`))
		os.Remove(fmt.Sprintf(`%s/%s`, bpf.BPF_FS, `f4gw_igr_ipv4`))
		os.Remove(fmt.Sprintf(`%s/%s`, bpf.BPF_FS, `f4gw_fc_v4`))
		os.Remove(fmt.Sprintf(`%s/%s`, bpf.BPF_FS, `f4gw_nat`))
		os.Remove(fmt.Sprintf(`%s/%s`, bpf.BPF_FS, `f4gw_progs`))
		return nil
	}

	if err := gw.bpfObjs.F4gwProgs.Update(FLM_DP_PKT_SLOW_PGM_ID,
		int32(gw.bpfObjs.XdpPacketSlowFunc.FD()), ebpf.UpdateAny); err != nil {
		log.Error().Msg(err.Error())
		return err
	}

	if err := gw.bpfObjs.F4gwProgs.Update(FLM_DP_CT_PGM_ID,
		int32(gw.bpfObjs.XdpConnTrackFunc.FD()), ebpf.UpdateAny); err != nil {
		log.Error().Msg(err.Error())
		return err
	}

	if err := gw.bpfObjs.F4gwProgs.Update(FLM_DP_PASS_PGM_ID,
		int32(gw.bpfObjs.XdpPass.FD()), ebpf.UpdateAny); err != nil {
		log.Error().Msg(err.Error())
		return err
	}

	if err := gw.bpfObjs.F4gwProgs.Update(FLM_DP_DROP_PGM_ID,
		int32(gw.bpfObjs.XdpDrop.FD()), ebpf.UpdateAny); err != nil {
		log.Error().Msg(err.Error())
		return err
	}

	return nil
}

func (gw *F4Gw) Close() {
	for msg, cb := range gw.cleanCallbacks {
		log.Info().Msg(msg)
		if err := cb(); err != nil {
			log.Error().Err(err)
		}
	}
}

func (gw *F4Gw) AttachIngressBPF(iface string) error {
	// Look up the network interface by name.
	ingressIface, ingressErr := net.InterfaceByName(iface)
	if ingressErr != nil {
		log.Error().Msgf("lookup network ingress iface %s: %s", iface, ingressErr)
		return ingressErr
	}
	// Attach the program.
	ingressLink, attachErr := link.AttachXDP(link.XDPOptions{
		Program:   gw.bpfObjs.XdpIngress,
		Interface: ingressIface.Index,
	})
	if attachErr != nil {
		log.Error().Msgf("could not attach XDP program: %s", attachErr)
		return attachErr
	}

	if addrs, addrErr := ingressIface.Addrs(); addrErr == nil {
		for _, addr := range addrs {
			if ipv4Addr := addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
				if ipNb, convErr := netaddr.IPv4ToInt(ipv4Addr); convErr == nil {
					if err := gw.bpfObjs.F4gwIgrIpv4.Update(ipNb,
						uint8(1), ebpf.UpdateAny); err != nil {
						log.Error().Msg(err.Error())
						return err
					}
				}
			}
		}
	}

	gw.cleanCallbacks[fmt.Sprintf("Detached XDP program to ingress iface %q (index %d)", ingressIface.Name, ingressIface.Index)] = ingressLink.Close

	log.Info().Msgf("Attached XDP program to ingress iface %q (index %d)", ingressIface.Name, ingressIface.Index)

	return nil
}

func (gw *F4Gw) AttachEgressBPF(iface string) error {
	// Look up the network interface by name.
	egressIface, egressErr := net.InterfaceByName(iface)
	if egressErr != nil {
		log.Error().Msgf("lookup network egress iface %s: %s", iface, egressErr)
		return egressErr
	}
	// Attach the program.
	egressLink, attachErr := link.AttachXDP(link.XDPOptions{
		Program:   gw.bpfObjs.XdpEgress,
		Interface: egressIface.Index,
	})
	if attachErr != nil {
		log.Error().Msgf("could not attach XDP program: %s", attachErr)
		return attachErr
	}

	if addrs, addrErr := egressIface.Addrs(); addrErr == nil {
		for _, addr := range addrs {
			if ipv4Addr := addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
				if ipNb, convErr := netaddr.IPv4ToInt(ipv4Addr); convErr == nil {
					if err := gw.bpfObjs.F4gwEgrIpv4.Update(ipNb,
						uint8(1), ebpf.UpdateAny); err != nil {
						log.Error().Msg(err.Error())
						return err
					}
				}
			}
		}
	}

	gw.cleanCallbacks[fmt.Sprintf("Detached XDP program to egress iface %q (index %d)", egressIface.Name, egressIface.Index)] = egressLink.Close

	log.Info().Msgf("Attached XDP program to  egress iface %q (index %d)", egressIface.Name, egressIface.Index)

	return nil
}

func (gw *F4Gw) ApplyNatLB(viaLink, viaIpAddr string, backends []F4GwBackend) error {
	if len(backends) == 0 {
		return nil
	}

	viaHWAddr, viaIfi, err := gw.linkQuery(viaLink)
	if err != nil {
		return err
	}

	viaIpNb, _ := netaddr.IPv4ToInt(net.ParseIP(viaIpAddr))
	gw.bpfObjs.F4gwEgrIpv4.Delete(viaIpNb)

	natKey := bpfDpNatKey{}
	natActs := bpfDpNatTacts{}
	natActs.Ca.ActType = DP_SET_SNAT
	natActs.SelType = NAT_LB_SEL_RR

	natActs.Nxfrm = uint16(len(backends))
	for index, backend := range backends {
		natActs.Nxfrms[index].NatXifi = uint16(viaIfi)
		natActs.Nxfrms[index].NatXip[0] = viaIpNb
		for n := 0; n < 6; n++ {
			natActs.Nxfrms[index].NatXmac[n] = viaHWAddr[n]
		}

		backendHWAddr, backendHWAddrErr := gw.arpQuery(viaLink, backend.IPv4)
		if backendHWAddrErr != nil {
			return backendHWAddrErr
		}

		natActs.Nxfrms[index].NatRip[0], _ = netaddr.IPv4ToInt(net.ParseIP(backend.IPv4))
		natActs.Nxfrms[index].NatRport = netaddr.HostToNetShort(backend.Port)
		for n := 0; n < 6; n++ {
			natActs.Nxfrms[index].NatRmac[n] = backendHWAddr[n]
		}
	}
	return gw.bpfObjs.F4gwNat.Update(&natKey, &natActs, ebpf.UpdateAny)
}

func (gw *F4Gw) linkQuery(ifaceName string) (net.HardwareAddr, int, error) {
	iface, ifaceErr := net.InterfaceByName(ifaceName)
	if ifaceErr != nil {
		log.Error().Msgf("lookup network iface %s: %s", ifaceName, ifaceErr)
		return nil, -1, ifaceErr
	}

	return iface.HardwareAddr, iface.Index, nil
}

func (gw *F4Gw) arpQuery(viaIface, ipAddr string) (net.HardwareAddr, error) {
	iface, ifaceErr := net.InterfaceByName(viaIface)
	if ifaceErr != nil {
		log.Error().Msgf("lookup network egress iface %s: %s", viaIface, ifaceErr)
		return nil, ifaceErr
	}

	client, clientErr := arp.Dial(iface)
	if clientErr != nil {
		log.Error().Err(clientErr)
		return nil, clientErr
	}

	defer client.Close()

	return client.Resolve(netip.MustParseAddr(ipAddr))
}
