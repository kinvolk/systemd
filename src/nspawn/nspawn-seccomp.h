#pragma once

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

#include <sys/types.h>

#include "seccomp-util.h"

typedef struct SyscallFilterSetCap {
        SyscallFilterSet filter;
        int capability;
} SyscallFilterSetCap;

enum {
        SYSCALL_FILTER_SET_CAP_SYSLOG,
        SYSCALL_FILTER_SET_CAP_SYS_MODULE,
        SYSCALL_FILTER_SET_CAP_SYS_PACCT,
        SYSCALL_FILTER_SET_CAP_SYS_PTRACE,
        SYSCALL_FILTER_SET_CAP_SYS_RAWIO,
        SYSCALL_FILTER_SET_CAP_SYS_TIME,
        _SYSCALL_FILTER_CAPS_SET_MAX
};

int setup_seccomp(uint64_t cap_list_retain, const char *system_call_filter);
