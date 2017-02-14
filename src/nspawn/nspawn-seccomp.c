/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <linux/netlink.h>
#include <sys/capability.h>
#include <sys/types.h>

#ifdef HAVE_SECCOMP
#include <seccomp.h>
#endif

#include "alloc-util.h"
#include "log.h"
#include "nspawn-seccomp.h"
#ifdef HAVE_SECCOMP
#include "seccomp-util.h"
#endif
#include "string-util.h"

#ifdef HAVE_SECCOMP

const SyscallFilterSet default_syscall_filter = {
        .name = "@nspawn_default",
        .help = "System calls filter for systemd-nspawn",
        .value =
        "_sysctl\0"
        "add_key\0"
        "afs_syscall\0"
        "bdflush\0"
        "bpf\0"
        "break\0"
        "create_module\0"
        "ftime\0"
        "get_kernel_syms\0"
        "getpmsg\0"
        "gtty\0"
        "kexec_file_load\0"
        "kexec_load\0"
        "keyctl\0"
        "lock\0"
        "lookup_dcookie\0"
        "mpx\0"
        "ngsservctl\0"
        "open_by_handle_at\0"
        "perf_event_open\0"
        "prof\0"
        "profil\0"
        "putpmsg\0"
        "query_module\0"
        "quotactl\0"
        "request_key\0"
        "security\0"
        "sgetmask\0"
        "ssetmask\0"
        "stty\0"
        "swapoff\0"
        "swapon\0"
        "sysfs\0"
        "tuxcall\0"
        "ulimit\0"
        "uselib\0"
        "ustat\0"
        "vserver\0"
};

const SyscallFilterSetCap syscall_filter_caps_sets[_SYSCALL_FILTER_CAPS_SET_MAX] = {
        [SYSCALL_FILTER_SET_CAP_SYSLOG] = {
                .filter = {
                        .name = "@nspawn_cap_syslog",
                        .help = "System calls to be disabled when CAP_SYSLOG is not set",
                        .value =
                        "syslog\0"
                },
                .capability = CAP_SYSLOG
        },
        [SYSCALL_FILTER_SET_CAP_SYS_MODULE] = {
                .filter = {
                        .name = "@nspawn_cap_sys_module",
                        .help = "System calls to be disabled when CAP_SYS_MODULE is not set",
                        .value =
                        "delete_module\0"
                        "finit_module\0"
                        "init_module\0"
                },
                .capability = CAP_SYS_MODULE
        },
        [SYSCALL_FILTER_SET_CAP_SYS_PACCT] = {
                .filter = {
                        .name = "@nspawn_cap_sys_pacct",
                        .help = "System calls to be disabled when CAP_SYS_PACCT is not set",
                        .value =
                        "acct\0"
                },
                .capability = CAP_SYS_PACCT
        },
        [SYSCALL_FILTER_SET_CAP_SYS_PTRACE] = {
                .filter = {
                        .name = "@nspawn_cap_sys_ptrace",
                        .help = "System calls to be disabled when CAP_SYS_PTRACE is not set",
                        .value =
                        "process_vm_readv\0"
                        "process_vm_writev\0"
                        "ptrace\0"
                },
                .capability = CAP_SYS_PTRACE
        },
        [SYSCALL_FILTER_SET_CAP_SYS_RAWIO] = {
                .filter = {
                        .name = "@nspawn_cap_sys_rawio",
                        .help = "System calls to be disabled when CAP_SYS_RAWIO is not set",
                        .value =
                        "ioperm\0"
                        "iopl\0"
                        "pciconfig_iobase\0"
                        "pciconfig_read\0"
                        "pciconfig_write\0"
#ifdef __NR_s390_pci_mmio_read
                        "s390_pci_mmio_read\0"
#endif
#ifdef __NR_s390_pci_mmio_write
                        "s390_pci_mmio_write\0"
#endif
                },
                .capability = CAP_SYS_RAWIO
        },
        [SYSCALL_FILTER_SET_CAP_SYS_TIME] = {
                .filter = {
                        .name = "@nspawn_cap_sys_time",
                        .help = "System calls to be disabled when CAP_SYS_TIME is not set",
                        .value =
                        "adjtimex\0"
                        "clock_adjtime\0"
                        "clock_settime\0"
                        "settimeofday\0"
                        "stime\0"
                },
                .capability = CAP_SYS_TIME
        },
};

static int seccomp_add_syscall_filters(
                scmp_filter_ctx ctx,
                uint32_t arch,
                uint64_t cap_list_retain,
                const char *system_call_filter) {
        unsigned i;
        int r;

        if (system_call_filter != NULL) {
                SyscallFilterSet syscall_filter = {
                        .name = "@nspawn_custom",
                        .help = "",
                        .value = system_call_filter
                };

                r = seccomp_add_syscall_filter_set(ctx, SCMP_ACT_ERRNO(EPERM), &syscall_filter, 0);
                if (r < 0)
                        log_debug_errno(r, "Failed to add rules from the command line, ignoring: %m");
        } else {
                r = seccomp_add_syscall_filter_set(ctx, SCMP_ACT_ERRNO(EPERM), &default_syscall_filter, 0);
                if (r < 0)
                        log_debug_errno(r, "Failed to add default filter set, ignoring: %m");

                for (i = 0; i < _SYSCALL_FILTER_CAPS_SET_MAX; i++) {
                        if (cap_list_retain & (1ULL << syscall_filter_caps_sets[i].capability))
                                continue;

                        r = seccomp_add_syscall_filter_set(ctx, SCMP_ACT_ERRNO(EPERM), &syscall_filter_caps_sets[i].filter, 0);
                        if (r < 0)
                                log_debug_errno(r, "Failed to add rules for capability, ignoring: %m");
                }
        }

        return 0;
}

int setup_seccomp(uint64_t cap_list_retain, const char *system_call_filter) {
        uint32_t arch;
        int r;

        if (!is_seccomp_available()) {
                log_debug("SECCOMP features not detected in the kernel, disabling SECCOMP audit filter");
                return 0;
        }

        SECCOMP_FOREACH_LOCAL_ARCH(arch) {
                _cleanup_(seccomp_releasep) scmp_filter_ctx seccomp = NULL;
                int n;

                log_debug("Operating on architecture: %s", seccomp_arch_to_string(arch));

                r = seccomp_init_for_arch(&seccomp, arch, SCMP_ACT_ALLOW);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate seccomp object: %m");

                n = seccomp_add_syscall_filters(seccomp, arch, cap_list_retain, system_call_filter);
                if (n < 0)
                        return n;

                /*
                  Audit is broken in containers, much of the userspace audit hookup will fail if running inside a
                  container. We don't care and just turn off creation of audit sockets.

                  This will make socket(AF_NETLINK, *, NETLINK_AUDIT) fail with EAFNOSUPPORT which audit userspace uses
                  as indication that audit is disabled in the kernel.
                */

                r = seccomp_rule_add_exact(
                                seccomp,
                                SCMP_ACT_ERRNO(EAFNOSUPPORT),
                                SCMP_SYS(socket),
                                2,
                                SCMP_A0(SCMP_CMP_EQ, AF_NETLINK),
                                SCMP_A2(SCMP_CMP_EQ, NETLINK_AUDIT));
                if (r < 0)
                        log_debug_errno(r, "Failed to add audit seccomp rule, ignoring: %m");
                else
                        n++;

                if (n <= 0) /* no rule added? then skip this architecture */
                        continue;

                r = seccomp_load(seccomp);
                if (IN_SET(r, -EPERM, -EACCES))
                        return log_error_errno(r, "Failed to install seccomp audit filter: %m");
                if (r < 0)
                        log_debug_errno(r, "Failed to install filter set for architecture %s, skipping: %m", seccomp_arch_to_string(arch));
        }

        return 0;
}

#else

int setup_seccomp(uint64_t cap_list_retain) {
        return 0;
}

#endif
