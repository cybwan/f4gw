package main

import "C"
import (
	"fmt"
	"time"

	"github.com/cybwan/f4gw/pkg/libbpf"
)

func main() {
	ret, err := libbpf.MountBpfFS("/sys/fs/bpf")
	fmt.Println(ret, err)
	bpffs := libbpf.IsBpfFS("/sys/fs/bpf")
	fmt.Println("bpffs:", bpffs)
	numPossibleCPUs, _ := libbpf.NumPossibleCPUs()
	fmt.Println("numPossibleCPUs:", numPossibleCPUs)

	err = libbpf.LoadAll(`/sys/fs/bpf`, `gateway`, `/root/gateway.kern.o`)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	err = libbpf.AttachXDP(`lo`, `/sys/fs/bpf/gateway/xdp_ingress`)
	if err != nil {
		fmt.Println("AttachXDP", err.Error())
		return
	}

	time.Sleep(time.Second * 3600)

	//err = libbpf.UnloadAll(`/sys/fs/bpf`, `gateway`)
	//if err != nil {
	//	fmt.Println(err.Error())
	//	return
	//}

	//test_fd, _ := libbpf.OpenObjPinned("/sys/fs/bpf/f4gw_progs")
	//fmt.Println("test_fd:", test_fd)
	//
	//egress_fd, _ := libbpf.OpenObjPinned("/sys/fs/bpf/gateway/xdp_egress")
	//fmt.Println("ingress_fd:", egress_fd)
	//
	//nat_map, _ := libbpf.GetMapByPinnedPath("/sys/fs/bpf/f4gw_nat")
	//fmt.Println("nat_map_fd:", nat_map)
	//
	//k := uint32(2)
	//if err := nat_map.Update(unsafe.Pointer(&k), unsafe.Pointer(&egress_fd)); err != nil {
	//	fmt.Println(err.Error())
	//}
	//
	//natKey := DpNatKey{}
	//natKey.Dport = 88
	//natKey.L4proto = 6
	//natKey.V6 = 0
	//
	//natActs := DpNatTacts{}
	//natActs.Ca.ActType = 99
	//natActs.Ito = 88888
	//
	//if err := nat_map.Update(unsafe.Pointer(&natKey), unsafe.Pointer(&natActs)); err != nil {
	//	fmt.Println(err.Error())
	//}
	//
	//bytes, err := nat_map.GetValue(unsafe.Pointer(&natKey))
	//if err != nil {
	//	fmt.Println(err.Error())
	//}
	//libbpf.Memcpy(unsafe.Pointer(&natActs), unsafe.Pointer(&bytes[0]), 1024)
	//fmt.Println(natActs.Ca.ActType)
	//
	//nat_map.Close()
}

type DpNatKey struct {
	Daddr   [4]uint32
	Dport   uint16
	Zone    uint16
	Mark    uint16
	L4proto uint8
	V6      uint8
}

type DpNatTacts struct {
	Ca struct {
		ActType uint8
		Ftrap   uint8
		Oaux    uint16
		Cidx    uint32
		Fwrid   uint32
		Mark    uint16
		Record  uint16
	}
	Ito     uint64
	Pto     uint64
	Lock    struct{ Val uint32 }
	Cdis    uint8
	_       [1]byte
	SelHint uint16
	SelType uint16
	Nxfrm   uint16
	Nxfrms  [16]struct {
		NatFlags uint8
		Inactive uint8
		Wprio    uint8
		Nv6      uint8
		Dsr      uint8
		Padding  uint8
		NatXifi  uint16
		NatXport uint16
		NatRport uint16
		NatXip   [4]uint32
		NatRip   [4]uint32
		NatXmac  [6]uint8
		NatRmac  [6]uint8
		Osp      uint16
		Odp      uint16
	}
	_      [4]byte
	Lts    uint64
	BaseTo uint64
}
