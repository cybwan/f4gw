package gateway

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
