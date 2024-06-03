// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package gateway

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	XdpConnTrackFunc  *ebpf.ProgramSpec `ebpf:"xdp_conn_track_func"`
	XdpDrop           *ebpf.ProgramSpec `ebpf:"xdp_drop"`
	XdpEgress         *ebpf.ProgramSpec `ebpf:"xdp_egress"`
	XdpIngress        *ebpf.ProgramSpec `ebpf:"xdp_ingress"`
	XdpPacketSlowFunc *ebpf.ProgramSpec `ebpf:"xdp_packet_slow_func"`
	XdpPass           *ebpf.ProgramSpec `ebpf:"xdp_pass"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	F4gwCt      *ebpf.MapSpec `ebpf:"f4gw_ct"`
	F4gwCtCtr   *ebpf.MapSpec `ebpf:"f4gw_ct_ctr"`
	F4gwEgrIpv4 *ebpf.MapSpec `ebpf:"f4gw_egr_ipv4"`
	F4gwFcV4    *ebpf.MapSpec `ebpf:"f4gw_fc_v4"`
	F4gwFcas    *ebpf.MapSpec `ebpf:"f4gw_fcas"`
	F4gwIgrIpv4 *ebpf.MapSpec `ebpf:"f4gw_igr_ipv4"`
	F4gwNat     *ebpf.MapSpec `ebpf:"f4gw_nat"`
	F4gwNatEp   *ebpf.MapSpec `ebpf:"f4gw_nat_ep"`
	F4gwNatOpts *ebpf.MapSpec `ebpf:"f4gw_nat_opts"`
	F4gwProgs   *ebpf.MapSpec `ebpf:"f4gw_progs"`
	F4gwXctk    *ebpf.MapSpec `ebpf:"f4gw_xctk"`
	F4gwXfck    *ebpf.MapSpec `ebpf:"f4gw_xfck"`
	F4gwXfrms   *ebpf.MapSpec `ebpf:"f4gw_xfrms"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	F4gwCt      *ebpf.Map `ebpf:"f4gw_ct"`
	F4gwCtCtr   *ebpf.Map `ebpf:"f4gw_ct_ctr"`
	F4gwEgrIpv4 *ebpf.Map `ebpf:"f4gw_egr_ipv4"`
	F4gwFcV4    *ebpf.Map `ebpf:"f4gw_fc_v4"`
	F4gwFcas    *ebpf.Map `ebpf:"f4gw_fcas"`
	F4gwIgrIpv4 *ebpf.Map `ebpf:"f4gw_igr_ipv4"`
	F4gwNat     *ebpf.Map `ebpf:"f4gw_nat"`
	F4gwNatEp   *ebpf.Map `ebpf:"f4gw_nat_ep"`
	F4gwNatOpts *ebpf.Map `ebpf:"f4gw_nat_opts"`
	F4gwProgs   *ebpf.Map `ebpf:"f4gw_progs"`
	F4gwXctk    *ebpf.Map `ebpf:"f4gw_xctk"`
	F4gwXfck    *ebpf.Map `ebpf:"f4gw_xfck"`
	F4gwXfrms   *ebpf.Map `ebpf:"f4gw_xfrms"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.F4gwCt,
		m.F4gwCtCtr,
		m.F4gwEgrIpv4,
		m.F4gwFcV4,
		m.F4gwFcas,
		m.F4gwIgrIpv4,
		m.F4gwNat,
		m.F4gwNatEp,
		m.F4gwNatOpts,
		m.F4gwProgs,
		m.F4gwXctk,
		m.F4gwXfck,
		m.F4gwXfrms,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	XdpConnTrackFunc  *ebpf.Program `ebpf:"xdp_conn_track_func"`
	XdpDrop           *ebpf.Program `ebpf:"xdp_drop"`
	XdpEgress         *ebpf.Program `ebpf:"xdp_egress"`
	XdpIngress        *ebpf.Program `ebpf:"xdp_ingress"`
	XdpPacketSlowFunc *ebpf.Program `ebpf:"xdp_packet_slow_func"`
	XdpPass           *ebpf.Program `ebpf:"xdp_pass"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.XdpConnTrackFunc,
		p.XdpDrop,
		p.XdpEgress,
		p.XdpIngress,
		p.XdpPacketSlowFunc,
		p.XdpPass,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_bpfel.o
var _BpfBytes []byte
