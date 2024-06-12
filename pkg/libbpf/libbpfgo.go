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
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

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
	output, err := cmd.Output()
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println(string(output))
	}
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

var (
	rlimitMu sync.Mutex
)

func RemoveMemlock() error {
	rlimitMu.Lock()
	defer rlimitMu.Unlock()

	// pid 0 affects the current process. Requires CAP_SYS_RESOURCE.
	newLimit := unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}
	if err := unix.Prlimit(0, unix.RLIMIT_MEMLOCK, &newLimit, nil); err != nil {
		return fmt.Errorf("failed to set memlock rlimit: %w", err)
	}

	return nil
}
