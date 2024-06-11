#include "libbpfgo.h"

void p_err(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
    fprintf(stderr, "Error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
	va_end(ap);
}

void p_info(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
}

static bool is_bpffs(char *path)
{
	struct statfs st_fs;

	if (statfs(path, &st_fs) < 0)
		return false;

	return (unsigned long)st_fs.f_type == BPF_FS_MAGIC;
}

static int
mnt_fs(const char *target, const char *type, char *buff, size_t bufflen)
{
	bool bind_done = false;

	while (mount("", target, "none", MS_PRIVATE | MS_REC, NULL)) {
		if (errno != EINVAL || bind_done) {
			snprintf(buff, bufflen,
				 "mount --make-private %s failed: %s",
				 target, strerror(errno));
			return -1;
		}

		if (mount(target, target, "none", MS_BIND, NULL)) {
			snprintf(buff, bufflen,
				 "mount --bind %s %s failed: %s",
				 target, target, strerror(errno));
			return -1;
		}

		bind_done = true;
	}

	if (mount(type, target, type, 0, "mode=0700")) {
		snprintf(buff, bufflen, "mount -t %s %s %s failed: %s",
			 type, type, target, strerror(errno));
		return -1;
	}

	return 0;
}

int cgo_mount_bpffs(const char *name)
{
	char err_str[ERR_MAX_LEN];
	char *file;
	int err = 0;

	file = malloc(strlen(name) + 1);
	if (!file) {
		p_err("mem alloc failed");
		return -1;
	}

	strcpy(file, name);

	if (is_bpffs(file))
		/* nothing to do if already mounted */
		goto out_free;

	err = mnt_fs(file, "bpf", err_str, ERR_MAX_LEN);
	if (err) {
		err_str[ERR_MAX_LEN - 1] = '\0';
		p_err("can't mount BPF file system to pin the object (%s): %s",
		      name, err_str);
	}

out_free:
	free(file);
	return err;
}

struct bpf_map_info *cgo_bpf_map_info_new()
{
    struct bpf_map_info *info;
    info = calloc(1, sizeof(*info));
    if (!info)
        return NULL;

    return info;
}

__u32 cgo_bpf_map_info_size()
{
    return sizeof(struct bpf_map_info);
}

void cgo_bpf_map_info_free(struct bpf_map_info *info)
{
    free(info);
}

__u32 cgo_bpf_map_info_type(struct bpf_map_info *info)
{
    if (!info)
        return 0;

    return info->type;
}

__u32 cgo_bpf_map_info_id(struct bpf_map_info *info)
{
    if (!info)
        return 0;

    return info->id;
}

__u32 cgo_bpf_map_info_key_size(struct bpf_map_info *info)
{
    if (!info)
        return 0;

    return info->key_size;
}

__u32 cgo_bpf_map_info_value_size(struct bpf_map_info *info)
{
    if (!info)
        return 0;

    return info->value_size;
}

__u32 cgo_bpf_map_info_max_entries(struct bpf_map_info *info)
{
    if (!info)
        return 0;

    return info->max_entries;
}

__u32 cgo_bpf_map_info_map_flags(struct bpf_map_info *info)
{
    if (!info)
        return 0;

    return info->map_flags;
}

char *cgo_bpf_map_info_name(struct bpf_map_info *info)
{
    if (!info)
        return NULL;

    return info->name;
}

int cgo_open_obj_pinned(const char *path, bool quiet)
{
	char *pname;
	int fd = -1;

	pname = strdup(path);
	if (!pname) {
		if (!quiet)
			p_err("mem alloc failed");
		goto out_ret;
	}

	fd = bpf_obj_get(pname);
	if (fd < 0) {
		if (!quiet)
			p_err("bpf obj get (%s): %s", pname,
			      errno == EACCES && !is_bpffs(dirname(pname)) ?
			    "directory not in bpf file system (bpffs)" :
			    strerror(errno));
		goto out_free;
	}

out_free:
	free(pname);
out_ret:
	return fd;
}

bool cgo_is_bpffs(char *path) {
    return is_bpffs(path);
}