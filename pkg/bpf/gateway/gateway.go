package gateway

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cybwan/f4gw/pkg/bpf"
	"github.com/cybwan/f4gw/pkg/libbpf"
	"github.com/cybwan/f4gw/pkg/netaddr"
)

func (gw *F4Gw) Init() {
	if err := libbpf.RemoveMemlock(); err != nil {
		log.Fatal().Msgf("remove memlock error: %v", err)
	}

	gw.prog = "gateway"
	gw.progFile = fmt.Sprintf("%s.kern.o", gw.prog)

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

	slow_func_fd, err := libbpf.OpenObjPinned(fmt.Sprintf("%s/%s/%s", bpf.BPF_FS, gw.prog, "classifier_slow"))
	if err != nil {
		log.Fatal().Err(err).Msg(`loading xdp_slow_func`)
	}

	k := FLM_DP_PKT_SLOW_PGM_ID
	if err := prog_map.Update(unsafe.Pointer(&k), unsafe.Pointer(&slow_func_fd)); err != nil {
		log.Fatal().Err(err).Msg(`updating f4gw_progs`)
	}

	ct_func_fd, err := libbpf.OpenObjPinned(fmt.Sprintf("%s/%s/%s", bpf.BPF_FS, gw.prog, "classifier_ct"))
	if err != nil {
		log.Fatal().Err(err).Msg(`loading xdp_ct_func`)
	}

	k = FLM_DP_CT_PGM_ID
	if err := prog_map.Update(unsafe.Pointer(&k), unsafe.Pointer(&ct_func_fd)); err != nil {
		log.Fatal().Err(err).Msg(`updating f4gw_progs`)
	}

	pass_func_fd, err := libbpf.OpenObjPinned(fmt.Sprintf("%s/%s/%s", bpf.BPF_FS, gw.prog, "classifier_pass"))
	if err != nil {
		log.Fatal().Err(err).Msg(`loading xdp_pass`)
	}

	k = FLM_DP_PASS_PGM_ID
	if err := prog_map.Update(unsafe.Pointer(&k), unsafe.Pointer(&pass_func_fd)); err != nil {
		log.Fatal().Err(err).Msg(`updating f4gw_progs`)
	}

	drop_func_fd, err := libbpf.OpenObjPinned(fmt.Sprintf("%s/%s/%s", bpf.BPF_FS, gw.prog, "classifier_drop"))
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

func (gw *F4Gw) AttachTCBPF(iface string) {
	// Look up the network interface by name.
	ingressIface, ingressErr := net.InterfaceByName(iface)
	if ingressErr != nil {
		log.Fatal().Msgf("lookup network ingress iface %s: %s", iface, ingressErr)
		return
	}

	if !libbpf.ExistTCQDisc(iface) {
		libbpf.AddTCQDisc(iface)
	}

	libbpf.AttachTCIngress(iface, fmt.Sprintf("%s/%s/%s", bpf.BPF_FS, gw.prog, "classifier_ingress"))
	libbpf.AttachTCEgress(iface, fmt.Sprintf("%s/%s/%s", bpf.BPF_FS, gw.prog, "classifier_egress"))

	if addrs, addrErr := ingressIface.Addrs(); addrErr == nil {
		igr_ipv4_map, err := libbpf.GetMapByPinnedPath(fmt.Sprintf("%s/%s/%s", bpf.BPF_FS, gw.prog, "f4gw_igr_ipv4"))
		if err != nil {
			log.Fatal().Err(err).Msg(`loading f4gw_igr_ipv4`)
		}
		v := uint8(1)
		for _, addr := range addrs {
			if ipv4Addr := addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
				if ipNb, convErr := netaddr.IPv4ToInt(ipv4Addr); convErr == nil {
					if err := igr_ipv4_map.Update(unsafe.Pointer(&ipNb), unsafe.Pointer(&v)); err != nil {
						log.Fatal().Err(err).Msg(`updating f4gw_igr_ipv4`)
					}
				}
			}
		}
	}

	gw.cleanCallbacks[fmt.Sprintf("Detached tc ingress & egress iface %q (index %d)", ingressIface.Name, ingressIface.Index)] = func() error {
		libbpf.DetachTCIngress(iface)
		libbpf.DetachTCEgress(iface)
		return nil
	}

	log.Info().Msgf("Attached tc bpf program iface %s", ingressIface.Name)
}

func (gw *F4Gw) ApplyNatLB(
	dstProto L4Proto, dstAddr string, dstPort uint16,
	backends []F4GwBackend) error {
	if len(backends) == 0 {
		return nil
	}

	dstAddrNb, err := netaddr.IPv4ToInt(net.ParseIP(dstAddr))
	if err != nil {
		return err
	}

	natKey := DpNatKey{}
	natKey.Daddr[0] = dstAddrNb
	natKey.Dport = dstPort
	natKey.L4proto = uint8(dstProto)
	natKey.V6 = 0

	natActs := DpNatTacts{}
	natActs.Ca.ActType = uint8(DP_SET_DNAT)
	natActs.SelType = uint16(NAT_LB_SEL_RR)

	natActs.Nxfrm = uint16(len(backends))

	egr_ipv4_map, err := libbpf.GetMapByPinnedPath(fmt.Sprintf("%s/%s/%s", bpf.BPF_FS, gw.prog, "f4gw_egr_ipv4"))
	if err != nil {
		log.Fatal().Err(err).Msg(`loading f4gw_egr_ipv4`)
	}

	nat_map, err := libbpf.GetMapByPinnedPath(fmt.Sprintf("%s/%s/%s", bpf.BPF_FS, gw.prog, "f4gw_nat"))
	if err != nil {
		log.Fatal().Err(err).Msg(`loading f4gw_nat`)
	}

	for index, backend := range backends {
		viaHWAddr, viaIfi, err := gw.linkQuery(backend.ViaLinkName)
		if err != nil {
			return err
		}

		viaIpNb, err := netaddr.IPv4ToInt(net.ParseIP(backend.ViaLinkAddr))
		if err != nil {
			return err
		}

		egr_ipv4_map.Delete(unsafe.Pointer(&viaIpNb))

		natActs.Nxfrms[index].NatXifi = uint16(viaIfi)
		natActs.Nxfrms[index].NatXip[0] = viaIpNb
		for n := 0; n < 6; n++ {
			natActs.Nxfrms[index].NatXmac[n] = viaHWAddr[n]
		}

		natActs.Nxfrms[index].NatRip[0], err = netaddr.IPv4ToInt(net.ParseIP(backend.IPv4))
		if err != nil {
			return err
		}
		natActs.Nxfrms[index].NatRport = netaddr.HostToNetShort(backend.Port)

		if gw.attachedXdpLinks == nil {
			gw.attachedXdpLinks = make(map[string]uint8)
		}
		if _, attached := gw.attachedXdpLinks[backend.ViaLinkName]; !attached {
			gw.attachedXdpLinks[backend.ViaLinkName] = 1
		}
	}
	return nat_map.Update(unsafe.Pointer(&natKey), unsafe.Pointer(&natActs))
}

func (gw *F4Gw) linkQuery(ifaceName string) (net.HardwareAddr, int, error) {
	iface, ifaceErr := net.InterfaceByName(ifaceName)
	if ifaceErr != nil {
		log.Error().Msgf("lookup network iface %s: %s", ifaceName, ifaceErr)
		return nil, -1, ifaceErr
	}

	return iface.HardwareAddr, iface.Index, nil
}
