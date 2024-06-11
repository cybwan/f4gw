package gateway

import (
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	"github.com/mdlayher/arp"

	"github.com/cybwan/f4gw/pkg/bpf"
	"github.com/cybwan/f4gw/pkg/libbpf"
)

func (gw *F4Gw) Init() {
	if err := libbpf.RemoveMemlock(); err != nil {
		log.Fatal().Msgf("remove memlock error: %v", err)
	}

	gw.prog = "gateway"
	gw.progFile = fmt.Sprintf("%s.kern", gw.prog)

	gw.cleanCallbacks = make(map[string]func() error)

	if !libbpf.IsBpfFS(bpf.BPF_FS) {
		success, err := libbpf.MountBpfFS(bpf.BPF_FS)
		if err != nil {
			log.Fatal().Err(err).Msg(`mount bpf file system`)
		}
		if !success {
			log.Fatal().Msg(`mount bpf file system error`)
		}
	}

	if err := libbpf.UnloadAll(bpf.BPF_FS, gw.prog); err != nil {
		log.Fatal().Err(err).Msg(`unloading bpf objects`)
	}

	if err := libbpf.LoadAll(bpf.BPF_FS, gw.prog, gw.progFile); err != nil {
		log.Fatal().Err(err).Msg(`loading bpf objects`)
	}

	gw.cleanCallbacks[`clean bpf Objects`] = func() error {
		libbpf.UnloadAll(bpf.BPF_FS, gw.prog)
		return nil
	}

	prog_map, err := libbpf.GetMapByPinnedPath(fmt.Sprintf("%s/%s/%s", bpf.BPF_FS, gw.prog, "f4gw_progs"))
	if err != nil {
		log.Fatal().Err(err).Msg(`loading f4gw_progs`)
	}

	slow_func_fd, err := libbpf.OpenObjPinned(fmt.Sprintf("%s/%s/%s", bpf.BPF_FS, gw.prog, "xdp_slow_func"))
	if err != nil {
		log.Fatal().Err(err).Msg(`loading xdp_slow_func`)
	}

	k := FLM_DP_PKT_SLOW_PGM_ID
	if err := prog_map.Update(unsafe.Pointer(&k), unsafe.Pointer(&slow_func_fd)); err != nil {
		log.Fatal().Err(err).Msg(`updating f4gw_progs`)
	}

	ct_func_fd, err := libbpf.OpenObjPinned(fmt.Sprintf("%s/%s/%s", bpf.BPF_FS, gw.prog, "xdp_ct_func"))
	if err != nil {
		log.Fatal().Err(err).Msg(`loading xdp_ct_func`)
	}

	k = FLM_DP_CT_PGM_ID
	if err := prog_map.Update(unsafe.Pointer(&k), unsafe.Pointer(&ct_func_fd)); err != nil {
		log.Fatal().Err(err).Msg(`updating f4gw_progs`)
	}

	pass_func_fd, err := libbpf.OpenObjPinned(fmt.Sprintf("%s/%s/%s", bpf.BPF_FS, gw.prog, "xdp_pass"))
	if err != nil {
		log.Fatal().Err(err).Msg(`loading xdp_pass`)
	}

	k = FLM_DP_PASS_PGM_ID
	if err := prog_map.Update(unsafe.Pointer(&k), unsafe.Pointer(&pass_func_fd)); err != nil {
		log.Fatal().Err(err).Msg(`updating f4gw_progs`)
	}

	drop_func_fd, err := libbpf.OpenObjPinned(fmt.Sprintf("%s/%s/%s", bpf.BPF_FS, gw.prog, "xdp_drop"))
	if err != nil {
		log.Fatal().Err(err).Msg(`loading xdp_pass`)
	}

	k = FLM_DP_DROP_PGM_ID
	if err := prog_map.Update(unsafe.Pointer(&k), unsafe.Pointer(&drop_func_fd)); err != nil {
		log.Fatal().Err(err).Msg(`updating f4gw_progs`)
	}
}

func (gw *F4Gw) Close() {
	for msg, cb := range gw.cleanCallbacks {
		log.Info().Msg(msg)
		if err := cb(); err != nil {
			log.Error().Err(err)
		}
	}
}

func (gw *F4Gw) AttachIngressBPF(iface string) {
	//// Look up the network interface by name.
	//ingressIface, ingressErr := net.InterfaceByName(iface)
	//if ingressErr != nil {
	//	log.Fatal().Msgf("lookup network ingress iface %s: %s", iface, ingressErr)
	//	return
	//}
	//// Attach the program.
	//ingressLink, ingressErr := link.AttachXDP(link.XDPOptions{
	//	Program:   gw.bpfObjs.XdpIngress,
	//	Interface: ingressIface.Index,
	//})
	//if ingressErr != nil {
	//	log.Fatal().Msgf("could not attach XDP program: %s", ingressErr)
	//	return
	//}
	//
	//if addrs, addrErr := ingressIface.Addrs(); addrErr == nil {
	//	for _, addr := range addrs {
	//		if ipv4Addr := addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
	//			if ipNb, convErr := netaddr.IPv4ToInt(ipv4Addr); convErr == nil {
	//				if err := gw.bpfObjs.F4gwIgrIpv4.Update(ipNb,
	//					uint8(1), ebpf.UpdateAny); err != nil {
	//					log.Fatal().Msgf(err.Error())
	//					return
	//				}
	//			}
	//		}
	//	}
	//}
	//
	//gw.cleanCallbacks[fmt.Sprintf("Detached XDP program to ingress iface %q (index %d)", ingressIface.Name, ingressIface.Index)] = ingressLink.Close
	//
	//log.Info().Msgf("Attached XDP program to ingress iface %q (index %d)", ingressIface.Name, ingressIface.Index)
}

func (gw *F4Gw) AttachEgressBPF(iface string) {
	//// Look up the network interface by name.
	//egressIface, egressErr := net.InterfaceByName(iface)
	//if egressErr != nil {
	//	log.Fatal().Msgf("lookup network egress iface %s: %s", iface, egressErr)
	//	return
	//}
	//// Attach the program.
	//egressLink, egressErr := link.AttachXDP(link.XDPOptions{
	//	Program:   gw.bpfObjs.XdpEgress,
	//	Interface: egressIface.Index,
	//})
	//if egressErr != nil {
	//	log.Fatal().Msgf("could not attach XDP program: %s", egressErr)
	//	return
	//}
	//
	//if addrs, addrErr := egressIface.Addrs(); addrErr == nil {
	//	for _, addr := range addrs {
	//		if ipv4Addr := addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
	//			if ipNb, convErr := netaddr.IPv4ToInt(ipv4Addr); convErr == nil {
	//				if err := gw.bpfObjs.F4gwEgrIpv4.Update(ipNb,
	//					uint8(1), ebpf.UpdateAny); err != nil {
	//					log.Fatal().Err(err)
	//					return
	//				}
	//			}
	//		}
	//	}
	//}
	//
	//gw.cleanCallbacks[fmt.Sprintf("Detached XDP program to egress iface %q (index %d)", egressIface.Name, egressIface.Index)] = egressLink.Close
	//
	//log.Info().Msgf("Attached XDP program to  egress iface %q (index %d)", egressIface.Name, egressIface.Index)
}

func (gw *F4Gw) ApplyNatLB(
	dstProto L4Proto, dstAddr string, dstPort uint16,
	backends []F4GwBackend) error {
	if len(backends) == 0 {
		return nil
	}
	//
	//dstAddrNb, err := netaddr.IPv4ToInt(net.ParseIP(dstAddr))
	//if err != nil {
	//	return err
	//}
	//
	//natKey := DpNatKey{}
	//natKey.Daddr[0] = dstAddrNb
	//natKey.Dport = dstPort
	//natKey.L4proto = uint8(dstProto)
	//natKey.V6 = 0
	//
	//natActs := DpNatTacts{}
	//natActs.Ca.ActType = uint8(DP_SET_SNAT)
	//natActs.SelType = uint16(NAT_LB_SEL_RR)
	//
	//natActs.Nxfrm = uint16(len(backends))
	//for index, backend := range backends {
	//	viaHWAddr, viaIfi, err := gw.linkQuery(backend.ViaLinkName)
	//	if err != nil {
	//		return err
	//	}
	//
	//	viaIpNb, err := netaddr.IPv4ToInt(net.ParseIP(backend.ViaLinkAddr))
	//	if err != nil {
	//		return err
	//	}
	//
	//	gw.bpfObjs.F4gwEgrIpv4.Delete(viaIpNb)
	//
	//	natActs.Nxfrms[index].NatXifi = uint16(viaIfi)
	//	natActs.Nxfrms[index].NatXip[0] = viaIpNb
	//	for n := 0; n < 6; n++ {
	//		natActs.Nxfrms[index].NatXmac[n] = viaHWAddr[n]
	//	}
	//
	//	backendHWAddr, backendHWAddrErr := gw.arpQuery(backend.ViaLinkName, backend.IPv4)
	//	if backendHWAddrErr != nil {
	//		return backendHWAddrErr
	//	}
	//
	//	natActs.Nxfrms[index].NatRip[0], err = netaddr.IPv4ToInt(net.ParseIP(backend.IPv4))
	//	if err != nil {
	//		return err
	//	}
	//	natActs.Nxfrms[index].NatRport = netaddr.HostToNetShort(backend.Port)
	//	for n := 0; n < 6; n++ {
	//		natActs.Nxfrms[index].NatRmac[n] = backendHWAddr[n]
	//	}
	//
	//	if gw.attachedXdpLinks == nil {
	//		gw.attachedXdpLinks = make(map[string]uint8)
	//	}
	//	if _, attached := gw.attachedXdpLinks[backend.ViaLinkName]; !attached {
	//		gw.AttachEgressBPF(backend.ViaLinkName)
	//		gw.attachedXdpLinks[backend.ViaLinkName] = 1
	//	}
	//}
	//return gw.bpfObjs.F4gwNat.Update(&natKey, &natActs, ebpf.UpdateAny)

	return nil
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
