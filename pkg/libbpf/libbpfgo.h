#ifndef __LIBBPF_GO_H__
#define __LIBBPF_GO_H__

#define BPF_FS_MAGIC 0xcafe4a11

#ifdef __powerpc64__
    #define __SANE_USERSPACE_TYPES__ 1
#endif

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <libgen.h>
#include <sys/resource.h>
#include <sys/mount.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h> // uapi

#define ERR_MAX_LEN	1024

struct bpf_map_info *cgo_bpf_map_info_new();
__u32 cgo_bpf_map_info_size();
void cgo_bpf_map_info_free(struct bpf_map_info *info);

bool cgo_is_bpffs(char *path);
int cgo_mount_bpffs(const char *name);

int cgo_open_obj_pinned(const char *path, bool quiet);

// bpf_map_info

__u32 cgo_bpf_map_info_type(struct bpf_map_info *info);
__u32 cgo_bpf_map_info_id(struct bpf_map_info *info);
__u32 cgo_bpf_map_info_key_size(struct bpf_map_info *info);
__u32 cgo_bpf_map_info_value_size(struct bpf_map_info *info);
__u32 cgo_bpf_map_info_max_entries(struct bpf_map_info *info);
__u32 cgo_bpf_map_info_map_flags(struct bpf_map_info *info);
char *cgo_bpf_map_info_name(struct bpf_map_info *info);

#endif
