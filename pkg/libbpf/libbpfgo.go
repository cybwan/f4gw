package libbpf

/*
#cgo LDFLAGS: -lelf -lz
#include "libbpfgo.h"
*/
import "C"

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"
)

//
// Version
//

// MajorVersion returns the major semver version of libbpf.
func MajorVersion() int {
	return C.LIBBPF_MAJOR_VERSION
}

// MinorVersion returns the minor semver version of libbpf.
func MinorVersion() int {
	return C.LIBBPF_MINOR_VERSION
}

// LibbpfVersionString returns the string representation of the libbpf version which
// libbpfgo is linked against
func LibbpfVersionString() string {
	return fmt.Sprintf("v%d.%d", MajorVersion(), MinorVersion())
}

//
// Strict Mode
//

// LibbpfStrictMode is an enum as defined in https://github.com/libbpf/libbpf/blob/2cd2d03f63242c048a896179398c68d2dbefe3d6/src/libbpf_legacy.h#L23
type LibbpfStrictMode uint32

const (
	LibbpfStrictModeAll               LibbpfStrictMode = C.LIBBPF_STRICT_ALL
	LibbpfStrictModeNone              LibbpfStrictMode = C.LIBBPF_STRICT_NONE
	LibbpfStrictModeCleanPtrs         LibbpfStrictMode = C.LIBBPF_STRICT_CLEAN_PTRS
	LibbpfStrictModeDirectErrs        LibbpfStrictMode = C.LIBBPF_STRICT_DIRECT_ERRS
	LibbpfStrictModeSecName           LibbpfStrictMode = C.LIBBPF_STRICT_SEC_NAME
	LibbpfStrictModeNoObjectList      LibbpfStrictMode = C.LIBBPF_STRICT_NO_OBJECT_LIST
	LibbpfStrictModeAutoRlimitMemlock LibbpfStrictMode = C.LIBBPF_STRICT_AUTO_RLIMIT_MEMLOCK
	LibbpfStrictModeMapDefinitions    LibbpfStrictMode = C.LIBBPF_STRICT_MAP_DEFINITIONS
)

func (b LibbpfStrictMode) String() (str string) {
	x := map[LibbpfStrictMode]string{
		LibbpfStrictModeAll:               "LIBBPF_STRICT_ALL",
		LibbpfStrictModeNone:              "LIBBPF_STRICT_NONE",
		LibbpfStrictModeCleanPtrs:         "LIBBPF_STRICT_CLEAN_PTRS",
		LibbpfStrictModeDirectErrs:        "LIBBPF_STRICT_DIRECT_ERRS",
		LibbpfStrictModeSecName:           "LIBBPF_STRICT_SEC_NAME",
		LibbpfStrictModeNoObjectList:      "LIBBPF_STRICT_NO_OBJECT_LIST",
		LibbpfStrictModeAutoRlimitMemlock: "LIBBPF_STRICT_AUTO_RLIMIT_MEMLOCK",
		LibbpfStrictModeMapDefinitions:    "LIBBPF_STRICT_MAP_DEFINITIONS",
	}

	str, ok := x[b]
	if !ok {
		str = LibbpfStrictModeNone.String()
	}

	return str
}

// SetStrictMode is no-op as of libbpf v1.0
func SetStrictMode(mode LibbpfStrictMode) {
	C.libbpf_set_strict_mode(uint32(mode))
}

//
// Misc
//

func NumPossibleCPUs() (int, error) {
	nCPUsC := C.libbpf_num_possible_cpus()
	if nCPUsC < 0 {
		return 0, fmt.Errorf("failed to retrieve the number of CPUs: %w", syscall.Errno(-nCPUsC))
	}

	return int(nCPUsC), nil
}

func OpenObjPinned(path string) (int, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return -1, fmt.Errorf("invalid path: %s: %v", path, err)
	}

	absPathC := C.CString(absPath)
	defer C.free(unsafe.Pointer(absPathC))
	var quiet C.bool
	fd := C.cgo_open_obj_pinned(absPathC, quiet)
	return int(fd), nil
}

func IsBpfFS(path string) bool {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	absPathC := C.CString(absPath)
	defer C.free(unsafe.Pointer(absPathC))
	valid := C.cgo_is_bpffs(absPathC)
	return bool(valid)
}

func MountBpfFS(path string) (bool, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}

	absPathC := C.CString(absPath)
	defer C.free(unsafe.Pointer(absPathC))
	ret := C.cgo_mount_bpffs(absPathC)
	return ret == 0, nil
}

const (
	bpftool_cmd = `/usr/sbin/bpftool`
	ip_cmd      = `/usr/sbin/ip`
)

func LoadAll(bpffs, progName, progFile string) error {
	pindir := fmt.Sprintf("%s/%s", bpffs, progName)
	args := []string{
		`prog`,
		`loadall`,
		progFile,
		pindir,
		`pinmaps`,
		pindir,
	}
	cmd := exec.Command(bpftool_cmd, args...)
	_, err := cmd.Output()
	return err
}

func UnloadAll(bpffs, progName string) error {
	pindir := fmt.Sprintf("%s/%s", bpffs, progName)
	return os.RemoveAll(pindir)
}

func AttachXDP(dev, pinnedProg string) error {
	args := []string{
		`link`,
		`set`,
		`dev`,
		dev,
		`xdpgeneric`,
		`pinned`,
		pinnedProg,
	}
	cmd := exec.Command(ip_cmd, args...)
	_, err := cmd.Output()
	return err
}

func DetachXDP(dev string) error {
	args := []string{
		`link`,
		`set`,
		`dev`,
		dev,
		`xdpgeneric`,
		`off`,
	}
	cmd := exec.Command(ip_cmd, args...)
	_, err := cmd.Output()
	return err
}
