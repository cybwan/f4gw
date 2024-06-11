package libbpf

/*
#cgo LDFLAGS: -lelf -lz
#include "libbpfgo.h"
*/
import "C"
import (
	"fmt"
	"syscall"
	"unsafe"
)

type MapType uint32

const (
	MapTypeUnspec              MapType = C.BPF_MAP_TYPE_UNSPEC
	MapTypeHash                MapType = C.BPF_MAP_TYPE_HASH
	MapTypeArray               MapType = C.BPF_MAP_TYPE_ARRAY
	MapTypeProgArray           MapType = C.BPF_MAP_TYPE_PROG_ARRAY
	MapTypePerfEventArray      MapType = C.BPF_MAP_TYPE_PERF_EVENT_ARRAY
	MapTypePerCPUHash          MapType = C.BPF_MAP_TYPE_PERCPU_HASH
	MapTypePerCPUArray         MapType = C.BPF_MAP_TYPE_PERCPU_ARRAY
	MapTypeStackTrace          MapType = C.BPF_MAP_TYPE_STACK_TRACE
	MapTypeCgroupArray         MapType = C.BPF_MAP_TYPE_CGROUP_ARRAY
	MapTypeLRUHash             MapType = C.BPF_MAP_TYPE_LRU_HASH
	MapTypeLRUPerCPUHash       MapType = C.BPF_MAP_TYPE_LRU_PERCPU_HASH
	MapTypeLPMTrie             MapType = C.BPF_MAP_TYPE_LPM_TRIE
	MapTypeArrayOfMaps         MapType = C.BPF_MAP_TYPE_ARRAY_OF_MAPS
	MapTypeHashOfMaps          MapType = C.BPF_MAP_TYPE_HASH_OF_MAPS
	MapTypeDevMap              MapType = C.BPF_MAP_TYPE_DEVMAP
	MapTypeSockMap             MapType = C.BPF_MAP_TYPE_SOCKMAP
	MapTypeCPUMap              MapType = C.BPF_MAP_TYPE_CPUMAP
	MapTypeXSKMap              MapType = C.BPF_MAP_TYPE_XSKMAP
	MapTypeSockHash            MapType = C.BPF_MAP_TYPE_SOCKHASH
	MapTypeCgroupStorage       MapType = C.BPF_MAP_TYPE_CGROUP_STORAGE
	MapTypeReusePortSockArray  MapType = C.BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
	MapTypePerCPUCgroupStorage MapType = C.BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
	MapTypeQueue               MapType = C.BPF_MAP_TYPE_QUEUE
	MapTypeStack               MapType = C.BPF_MAP_TYPE_STACK
	MapTypeSKStorage           MapType = C.BPF_MAP_TYPE_SK_STORAGE
	MapTypeDevmapHash          MapType = C.BPF_MAP_TYPE_DEVMAP_HASH
)

// BPFMapInfo mirrors the C structure bpf_map_info.
type BPFMapInfo struct {
	FD         int
	ID         uint32
	Type       MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
	Name       string
}

// GetMapInfoByFD returns the BPFMapInfo for the map with the given file descriptor.
func GetMapInfoByFD(fd int) (*BPFMapInfo, error) {
	infoC := C.cgo_bpf_map_info_new()
	defer C.cgo_bpf_map_info_free(infoC)

	infoLenC := C.cgo_bpf_map_info_size()
	retC := C.bpf_obj_get_info_by_fd(C.int(fd), unsafe.Pointer(infoC), &infoLenC)
	if retC < 0 {
		return nil, fmt.Errorf("failed to get map info for fd %d: %w", fd, syscall.Errno(-retC))
	}

	return &BPFMapInfo{
		FD:         fd,
		ID:         uint32(C.cgo_bpf_map_info_id(infoC)),
		Type:       MapType(C.cgo_bpf_map_info_type(infoC)),
		KeySize:    uint32(C.cgo_bpf_map_info_key_size(infoC)),
		ValueSize:  uint32(C.cgo_bpf_map_info_value_size(infoC)),
		MaxEntries: uint32(C.cgo_bpf_map_info_max_entries(infoC)),
		MapFlags:   uint32(C.cgo_bpf_map_info_map_flags(infoC)),
		Name:       C.GoString(C.cgo_bpf_map_info_name(infoC)),
	}, nil
}

// CalcMapValueSize calculates the size of the value for a map.
// For per-CPU maps, it is calculated based on the number of possible CPUs.
func CalcMapValueSize(valueSize int, mapType MapType) (int, error) {
	if valueSize <= 0 {
		return 0, fmt.Errorf("value size must be greater than 0")
	}

	switch mapType {
	case MapTypePerCPUArray,
		MapTypePerCPUHash,
		MapTypeLRUPerCPUHash,
		MapTypePerCPUCgroupStorage:
		// per-CPU maps have a value size calculated using a round-up of the
		// element size multiplied by the number of possible CPUs.
		elemSize := roundUp(uint64(valueSize), 8)
		numCPU, err := NumPossibleCPUs()
		if err != nil {
			return 0, err
		}

		return int(elemSize) * numCPU, nil
	default:
		// For other maps, the value size does not change.
		return valueSize, nil
	}
}

// roundUp rounds x up to the nearest multiple of y.
func roundUp(x, y uint64) uint64 {
	return ((x + (y - 1)) / y) * y
}
