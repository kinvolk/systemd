/* SPDX-License-Identifier: LGPL-2.1-or-later */

#define LSM_MAP_BPFFS_PATH "/sys/fs/bpf/systemd/lsm_bpf_map"

int lsm_bpf_supported(void);
int lsm_bpf_setup(void);
int bpf_restrict_filesystems(char **filesystems, char *cgroup_path);
int cleanup_lsm_bpf(const char *cgroup_path);
