/*
** EPITECH PROJECT, 2024
** syscalls.h
** File description:
** syscalls header for strace
*/
#pragma once

#define SYSCALL_MAXARGS 6
#define INT 1
#define PTR 2
#define STR 3
#define NONE 4

typedef unsigned char value_type_t;

typedef struct syscall_s {
    const char *name;
    value_type_t args_value[SYSCALL_MAXARGS];
    value_type_t retval;
} syscall_t;

static const syscall_t syscalls[] = {
    [0] = {
        .retval = INT,
        .name = "read",
        .args_value = {INT, STR, INT, NONE, NONE, NONE},
    },
    [1] = {
        .retval = INT,
        .name = "write",
        .args_value = {INT, STR, INT, NONE, NONE, NONE},
    },
    [2] = {
        .retval = INT,
        .name = "open",
        .args_value = {STR, INT, NONE, NONE, NONE, NONE},
    },
    [3] = {
        .retval = INT,
        .name = "close",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [4] = {
        .retval = INT,
        .name = "stat",
        .args_value = {STR, PTR, NONE, NONE, NONE, NONE},
    },
    [5] = {
        .retval = INT,
        .name = "fstat",
        .args_value = {INT, PTR, NONE, NONE, NONE, NONE},
    },
    [6] = {
        .retval = INT,
        .name = "lstat",
        .args_value = {STR, PTR, NONE, NONE, NONE, NONE},
    },
    [7] = {
        .retval = INT,
        .name = "poll",
        .args_value = {PTR, INT, INT, NONE, NONE, NONE},
    },
    [8] = {
        .retval = INT,
        .name = "lseek",
        .args_value = {INT, INT, INT, NONE, NONE, NONE},
    },
    [9] = {
        .retval = PTR,
        .name = "mmap",
        .args_value = {PTR, INT, INT, INT, INT, INT},
    },
    [10] = {
        .retval = INT,
        .name = "mprotect",
        .args_value = {PTR, INT, INT, NONE, NONE, NONE},
    },
    [11] = {
        .retval = INT,
        .name = "munmap",
        .args_value = {PTR, INT, NONE, NONE, NONE, NONE},
    },
    [12] = {
        .retval = PTR,
        .name = "brk",
        .args_value = {PTR, NONE, NONE, NONE, NONE, NONE},
    },
    [13] = {
        .retval = INT,
        .name = "rt_sigaction",
        .args_value = {INT, PTR, PTR, INT, NONE, NONE},
    },
    [14] = {
        .retval = INT,
        .name = "rt_sigprocmask",
        .args_value = {INT, PTR, PTR, INT, NONE, NONE},
    },
    [15] = {
        .retval = INT,
        .name = "rt_sigreturn",
        .args_value = {PTR, PTR, PTR, PTR, PTR, PTR},
    },
    [16] = {
        .retval = INT,
        .name = "ioctl",
        .args_value = {INT, INT, INT, NONE, NONE, NONE},
    },
    [17] = {
        .retval = INT,
        .name = "pread64",
        .args_value = {INT, STR, INT, INT, NONE, NONE},
    },
    [18] = {
        .retval = INT,
        .name = "pwrite64",
        .args_value = {INT, STR, INT, INT, NONE, NONE},
    },
    [19] = {
        .retval = INT,
        .name = "readv",
        .args_value = {INT, PTR, INT, NONE, NONE, NONE},
    },
    [20] = {
        .retval = INT,
        .name = "writev",
        .args_value = {INT, PTR, INT, NONE, NONE, NONE},
    },
    [21] = {
        .retval = INT,
        .name = "access",
        .args_value = {STR, INT, NONE, NONE, NONE, NONE},
    },
    [22] = {
        .retval = INT,
        .name = "pipe",
        .args_value = {PTR, NONE, NONE, NONE, NONE, NONE},
    },
    [23] = {
        .retval = INT,
        .name = "select",
        .args_value = {INT, PTR, PTR, PTR, PTR, NONE},
    },
    [24] = {
        .retval = INT,
        .name = "sched_yield",
        .args_value = {NONE, NONE, NONE, NONE, NONE, NONE},
    },
    [25] = {
        .retval = INT,
        .name = "mremap",
        .args_value = {INT, INT, INT, INT, INT, NONE},
    },
    [26] = {
        .retval = INT,
        .name = "msync",
        .args_value = {INT, INT, INT, NONE, NONE, NONE},
    },
    [27] = {
        .retval = INT,
        .name = "mincore",
        .args_value = {INT, INT, PTR, NONE, NONE, NONE},
    },
    [28] = {
        .retval = INT,
        .name = "madvise",
        .args_value = {INT, INT, INT, NONE, NONE, NONE},
    },
    [29] = {
        .retval = INT,
        .name = "shmget",
        .args_value = {INT, INT, INT, NONE, NONE, NONE},
    },
    [30] = {
        .retval = INT,
        .name = "shmat",
        .args_value = {INT, STR, INT, NONE, NONE, NONE},
    },
    [31] = {
        .retval = INT,
        .name = "shmctl",
        .args_value = {INT, INT, PTR, NONE, NONE, NONE},
    },
    [32] = {
        .retval = INT,
        .name = "dup",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [33] = {
        .retval = INT,
        .name = "dup2",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [34] = {
        .retval = INT,
        .name = "pause",
        .args_value = {NONE, NONE, NONE, NONE, NONE, NONE},
    },
    [35] = {
        .retval = INT,
        .name = "nanosleep",
        .args_value = {PTR, PTR, NONE, NONE, NONE, NONE},
    },
    [36] = {
        .retval = INT,
        .name = "getitimer",
        .args_value = {INT, PTR, NONE, NONE, NONE, NONE},
    },
    [37] = {
        .retval = INT,
        .name = "alarm",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [38] = {
        .retval = INT,
        .name = "setitimer",
        .args_value = {INT, PTR, PTR, NONE, NONE, NONE},
    },
    [39] = {
        .retval = INT,
        .name = "getpid",
        .args_value = {NONE, NONE, NONE, NONE, NONE, NONE},
    },
    [40] = {
        .retval = INT,
        .name = "sendfile",
        .args_value = {INT, INT, PTR, INT, NONE, NONE},
    },
    [41] = {
        .retval = INT,
        .name = "socket",
        .args_value = {INT, INT, INT, NONE, NONE, NONE},
    },
    [42] = {
        .retval = INT,
        .name = "connect",
        .args_value = {INT, PTR, INT, NONE, NONE, NONE},
    },
    [43] = {
        .retval = INT,
        .name = "accept",
        .args_value = {INT, PTR, PTR, NONE, NONE, NONE},
    },
    [44] = {
        .retval = INT,
        .name = "sendto",
        .args_value = {INT, PTR, INT, INT, PTR, INT},
    },
    [45] = {
        .retval = INT,
        .name = "recvfrom",
        .args_value = {INT, PTR, INT, INT, PTR, PTR},
    },
    [46] = {
        .retval = INT,
        .name = "sendmsg",
        .args_value = {INT, PTR, INT, NONE, NONE, NONE},
    },
    [47] = {
        .retval = INT,
        .name = "recvmsg",
        .args_value = {INT, PTR, INT, NONE, NONE, NONE},
    },
    [48] = {
        .retval = INT,
        .name = "shutdown",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [49] = {
        .retval = INT,
        .name = "bind",
        .args_value = {INT, PTR, INT, NONE, NONE, NONE},
    },
    [50] = {
        .retval = INT,
        .name = "listen",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [51] = {
        .retval = INT,
        .name = "getsockname",
        .args_value = {INT, PTR, PTR, NONE, NONE, NONE},
    },
    [52] = {
        .retval = INT,
        .name = "getpeername",
        .args_value = {INT, PTR, PTR, NONE, NONE, NONE},
    },
    [53] = {
        .retval = INT,
        .name = "socketpair",
        .args_value = {INT, INT, INT, PTR, NONE, NONE},
    },
    [54] = {
        .retval = INT,
        .name = "setsockopt",
        .args_value = {INT, INT, INT, STR, INT, NONE},
    },
    [55] = {
        .retval = INT,
        .name = "getsockopt",
        .args_value = {INT, INT, INT, STR, PTR, NONE},
    },
    [56] = {
        .retval = INT,
        .name = "clone",
        .args_value = {INT, INT, PTR, PTR, INT, NONE},
    },
    [57] = {
        .retval = INT,
        .name = "fork",
        .args_value = {NONE, NONE, NONE, NONE, NONE, NONE},
    },
    [58] = {
        .retval = INT,
        .name = "vfork",
        .args_value = {NONE, NONE, NONE, NONE, NONE, NONE},
    },
    [59] = {
        .retval = INT,
        .name = "execve",
        .args_value = {STR, PTR, PTR, NONE, NONE, NONE},
    },
    [60] = {
        .retval = NONE,
        .name = "exit",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [61] = {
        .retval = INT,
        .name = "wait4",
        .args_value = {INT, PTR, INT, PTR, NONE, NONE},
    },
    [62] = {
        .retval = INT,
        .name = "kill",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [63] = {
        .retval = INT,
        .name = "uname",
        .args_value = {PTR, NONE, NONE, NONE, NONE, NONE},
    },
    [64] = {
        .retval = INT,
        .name = "semget",
        .args_value = {INT, INT, INT, NONE, NONE, NONE},
    },
    [65] = {
        .retval = INT,
        .name = "semop",
        .args_value = {INT, PTR, INT, NONE, NONE, NONE},
    },
    [66] = {
        .retval = INT,
        .name = "semctl",
        .args_value = {INT, INT, INT, INT, NONE, NONE},
    },
    [67] = {
        .retval = INT,
        .name = "shmdt",
        .args_value = {STR, NONE, NONE, NONE, NONE, NONE},
    },
    [68] = {
        .retval = INT,
        .name = "msgget",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [69] = {
        .retval = INT,
        .name = "msgsnd",
        .args_value = {INT, PTR, INT, INT, NONE, NONE},
    },
    [70] = {
        .retval = INT,
        .name = "msgrcv",
        .args_value = {INT, PTR, INT, INT, INT, NONE},
    },
    [71] = {
        .retval = INT,
        .name = "msgctl",
        .args_value = {INT, INT, PTR, NONE, NONE, NONE},
    },
    [72] = {
        .retval = INT,
        .name = "fcntl",
        .args_value = {INT, INT, INT, NONE, NONE, NONE},
    },
    [73] = {
        .retval = INT,
        .name = "flock",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [74] = {
        .retval = INT,
        .name = "fsync",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [75] = {
        .retval = INT,
        .name = "fdatasync",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [76] = {
        .retval = INT,
        .name = "truncate",
        .args_value = {STR, INT, NONE, NONE, NONE, NONE},
    },
    [77] = {
        .retval = INT,
        .name = "ftruncate",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [78] = {
        .retval = INT,
        .name = "getdents",
        .args_value = {INT, PTR, INT, NONE, NONE, NONE},
    },
    [79] = {
        .retval = INT,
        .name = "getcwd",
        .args_value = {STR, INT, NONE, NONE, NONE, NONE},
    },
    [80] = {
        .retval = INT,
        .name = "chdir",
        .args_value = {STR, NONE, NONE, NONE, NONE, NONE},
    },
    [81] = {
        .retval = INT,
        .name = "fchdir",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [82] = {
        .retval = INT,
        .name = "rename",
        .args_value = {STR, STR, NONE, NONE, NONE, NONE},
    },
    [83] = {
        .retval = INT,
        .name = "mkdir",
        .args_value = {STR, INT, NONE, NONE, NONE, NONE},
    },
    [84] = {
        .retval = INT,
        .name = "rmdir",
        .args_value = {STR, NONE, NONE, NONE, NONE, NONE},
    },
    [85] = {
        .retval = INT,
        .name = "creat",
        .args_value = {STR, INT, NONE, NONE, NONE, NONE},
    },
    [86] = {
        .retval = INT,
        .name = "link",
        .args_value = {STR, STR, NONE, NONE, NONE, NONE},
    },
    [87] = {
        .retval = INT,
        .name = "unlink",
        .args_value = {STR, NONE, NONE, NONE, NONE, NONE},
    },
    [88] = {
        .retval = INT,
        .name = "symlink",
        .args_value = {STR, STR, NONE, NONE, NONE, NONE},
    },
    [89] = {
        .retval = INT,
        .name = "readlink",
        .args_value = {STR, STR, INT, NONE, NONE, NONE},
    },
    [90] = {
        .retval = INT,
        .name = "chmod",
        .args_value = {STR, INT, NONE, NONE, NONE, NONE},
    },
    [91] = {
        .retval = INT,
        .name = "fchmod",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [92] = {
        .retval = INT,
        .name = "chown",
        .args_value = {STR, INT, INT, NONE, NONE, NONE},
    },
    [93] = {
        .retval = INT,
        .name = "fchown",
        .args_value = {INT, INT, INT, NONE, NONE, NONE},
    },
    [94] = {
        .retval = INT,
        .name = "lchown",
        .args_value = {STR, INT, INT, NONE, NONE, NONE},
    },
    [95] = {
        .retval = INT,
        .name = "umask",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [96] = {
        .retval = INT,
        .name = "gettimeofday",
        .args_value = {PTR, PTR, NONE, NONE, NONE, NONE},
    },
    [97] = {
        .retval = INT,
        .name = "getrlimit",
        .args_value = {INT, PTR, NONE, NONE, NONE, NONE},
    },
    [98] = {
        .retval = INT,
        .name = "getrusage",
        .args_value = {INT, PTR, NONE, NONE, NONE, NONE},
    },
    [99] = {
        .retval = INT,
        .name = "sysinfo",
        .args_value = {PTR, NONE, NONE, NONE, NONE, NONE},
    },
    [100] = {
        .retval = INT,
        .name = "times",
        .args_value = {PTR, NONE, NONE, NONE, NONE, NONE},
    },
    [101] = {
        .retval = INT,
        .name = "ptrace",
        .args_value = {INT, INT, INT, INT, NONE, NONE},
    },
    [102] = {
        .retval = INT,
        .name = "getuid",
        .args_value = {NONE, NONE, NONE, NONE, NONE, NONE},
    },
    [103] = {
        .retval = INT,
        .name = "syslog",
        .args_value = {INT, STR, INT, NONE, NONE, NONE},
    },
    [104] = {
        .retval = INT,
        .name = "getgid",
        .args_value = {NONE, NONE, NONE, NONE, NONE, NONE},
    },
    [105] = {
        .retval = INT,
        .name = "setuid",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [106] = {
        .retval = INT,
        .name = "setgid",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [107] = {
        .retval = INT,
        .name = "geteuid",
        .args_value = {NONE, NONE, NONE, NONE, NONE, NONE},
    },
    [108] = {
        .retval = INT,
        .name = "getegid",
        .args_value = {NONE, NONE, NONE, NONE, NONE, NONE},
    },
    [109] = {
        .retval = INT,
        .name = "setpgid",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [110] = {
        .retval = INT,
        .name = "getppid",
        .args_value = {NONE, NONE, NONE, NONE, NONE, NONE},
    },
    [111] = {
        .retval = INT,
        .name = "getpgrp",
        .args_value = {NONE, NONE, NONE, NONE, NONE, NONE},
    },
    [112] = {
        .retval = INT,
        .name = "setsid",
        .args_value = {NONE, NONE, NONE, NONE, NONE, NONE},
    },
    [113] = {
        .retval = INT,
        .name = "setreuid",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [114] = {
        .retval = INT,
        .name = "setregid",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [115] = {
        .retval = INT,
        .name = "getgroups",
        .args_value = {INT, PTR, NONE, NONE, NONE, NONE},
    },
    [116] = {
        .retval = INT,
        .name = "setgroups",
        .args_value = {INT, PTR, NONE, NONE, NONE, NONE},
    },
    [117] = {
        .retval = INT,
        .name = "setresuid",
        .args_value = {INT, INT, INT, NONE, NONE, NONE},
    },
    [118] = {
        .retval = INT,
        .name = "getresuid",
        .args_value = {PTR, PTR, PTR, NONE, NONE, NONE},
    },
    [119] = {
        .retval = INT,
        .name = "setresgid",
        .args_value = {INT, INT, INT, NONE, NONE, NONE},
    },
    [120] = {
        .retval = INT,
        .name = "getresgid",
        .args_value = {PTR, PTR, PTR, NONE, NONE, NONE},
    },
    [121] = {
        .retval = INT,
        .name = "getpgid",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [122] = {
        .retval = INT,
        .name = "setfsuid",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [123] = {
        .retval = INT,
        .name = "setfsgid",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [124] = {
        .retval = INT,
        .name = "getsid",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [125] = {
        .retval = INT,
        .name = "capget",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [126] = {
        .retval = INT,
        .name = "capset",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [127] = {
        .retval = INT,
        .name = "rt_sigpending",
        .args_value = {PTR, INT, NONE, NONE, NONE, NONE},
    },
    [128] = {
        .retval = INT,
        .name = "rt_sigtimedwait",
        .args_value = {PTR, PTR, PTR, INT, NONE, NONE},
    },
    [129] = {
        .retval = INT,
        .name = "rt_sigqueueinfo",
        .args_value = {INT, INT, PTR, NONE, NONE, NONE},
    },
    [130] = {
        .retval = INT,
        .name = "rt_sigsuspend",
        .args_value = {PTR, INT, NONE, NONE, NONE, NONE},
    },
    [131] = {
        .retval = INT,
        .name = "sigaltstack",
        .args_value = {PTR, PTR, NONE, NONE, NONE, NONE},
    },
    [132] = {
        .retval = INT,
        .name = "utime",
        .args_value = {STR, PTR, NONE, NONE, NONE, NONE},
    },
    [133] = {
        .retval = INT,
        .name = "mknod",
        .args_value = {STR, INT, INT, NONE, NONE, NONE},
    },
    [134] = {
        .retval = INT,
        .name = "uselib",
        .args_value = {STR, NONE, NONE, NONE, NONE, NONE},
    },
    [135] = {
        .retval = INT,
        .name = "personality",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [136] = {
        .retval = INT,
        .name = "ustat",
        .args_value = {INT, PTR, NONE, NONE, NONE, NONE},
    },
    [137] = {
        .retval = INT,
        .name = "statfs",
        .args_value = {STR, PTR, NONE, NONE, NONE, NONE},
    },
    [138] = {
        .retval = INT,
        .name = "fstatfs",
        .args_value = {INT, PTR, NONE, NONE, NONE, NONE},
    },
    [139] = {
        .retval = INT,
        .name = "sysfs",
        .args_value = {INT, INT, INT, NONE, NONE, NONE},
    },
    [140] = {
        .retval = INT,
        .name = "getpriority",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [141] = {
        .retval = INT,
        .name = "setpriority",
        .args_value = {INT, INT, INT, NONE, NONE, NONE},
    },
    [142] = {
        .retval = INT,
        .name = "sched_setparam",
        .args_value = {INT, PTR, NONE, NONE, NONE, NONE},
    },
    [143] = {
        .retval = INT,
        .name = "sched_getparam",
        .args_value = {INT, PTR, NONE, NONE, NONE, NONE},
    },
    [144] = {
        .retval = INT,
        .name = "sched_setscheduler",
        .args_value = {INT, INT, PTR, NONE, NONE, NONE},
    },
    [145] = {
        .retval = INT,
        .name = "sched_getscheduler",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [146] = {
        .retval = INT,
        .name = "sched_get_priority_max",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [147] = {
        .retval = INT,
        .name = "sched_get_priority_min",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [148] = {
        .retval = INT,
        .name = "sched_rr_get_interval",
        .args_value = {INT, PTR, NONE, NONE, NONE, NONE},
    },
    [149] = {
        .retval = INT,
        .name = "mlock",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [150] = {
        .retval = INT,
        .name = "munlock",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [151] = {
        .retval = INT,
        .name = "mlockall",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [152] = {
        .retval = INT,
        .name = "munlockall",
        .args_value = {NONE, NONE, NONE, NONE, NONE, NONE},
    },
    [153] = {
        .retval = INT,
        .name = "vhangup",
        .args_value = {NONE, NONE, NONE, NONE, NONE, NONE},
    },
    [154] = {
        .retval = INT,
        .name = "modify_ldt",
        .args_value = {PTR, PTR, PTR, PTR, PTR, PTR},
    },
    [155] = {
        .retval = INT,
        .name = "pivot_root",
        .args_value = {STR, STR, NONE, NONE, NONE, NONE},
    },
    [156] = {
        .retval = INT,
        .name = "_sysctl",
        .args_value = {PTR, PTR, PTR, PTR, PTR, PTR},
    },
    [157] = {
        .retval = INT,
        .name = "prctl",
        .args_value = {INT, INT, INT, INT, INT, NONE},
    },
    [158] = {
        .retval = INT,
        .name = "arch_prctl",
        .args_value = {INT, PTR, NONE, NONE, NONE, NONE},
    },
    [159] = {
        .retval = INT,
        .name = "adjtimex",
        .args_value = {PTR, NONE, NONE, NONE, NONE, NONE},
    },
    [160] = {
        .retval = INT,
        .name = "setrlimit",
        .args_value = {INT, PTR, NONE, NONE, NONE, NONE},
    },
    [161] = {
        .retval = INT,
        .name = "chroot",
        .args_value = {STR, NONE, NONE, NONE, NONE, NONE},
    },
    [162] = {
        .retval = INT,
        .name = "sync",
        .args_value = {NONE, NONE, NONE, NONE, NONE, NONE},
    },
    [163] = {
        .retval = INT,
        .name = "acct",
        .args_value = {STR, NONE, NONE, NONE, NONE, NONE},
    },
    [164] = {
        .retval = INT,
        .name = "settimeofday",
        .args_value = {PTR, PTR, NONE, NONE, NONE, NONE},
    },
    [165] = {
        .retval = INT,
        .name = "mount",
        .args_value = {STR, STR, STR, INT, PTR, NONE},
    },
    [166] = {
        .retval = INT,
        .name = "umount2",
        .args_value = {PTR, PTR, PTR, PTR, PTR, PTR},
    },
    [167] = {
        .retval = INT,
        .name = "swapon",
        .args_value = {STR, INT, NONE, NONE, NONE, NONE},
    },
    [168] = {
        .retval = INT,
        .name = "swapoff",
        .args_value = {STR, NONE, NONE, NONE, NONE, NONE},
    },
    [169] = {
        .retval = INT,
        .name = "reboot",
        .args_value = {INT, INT, INT, PTR, NONE, NONE},
    },
    [170] = {
        .retval = INT,
        .name = "sethostname",
        .args_value = {STR, INT, NONE, NONE, NONE, NONE},
    },
    [171] = {
        .retval = INT,
        .name = "setdomainname",
        .args_value = {STR, INT, NONE, NONE, NONE, NONE},
    },
    [172] = {
        .retval = INT,
        .name = "iopl",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [173] = {
        .retval = INT,
        .name = "ioperm",
        .args_value = {PTR, PTR, PTR, PTR, PTR, PTR},
    },
    [174] = {
        .retval = INT,
        .name = "create_module",
        .args_value = {PTR, PTR, PTR, PTR, PTR, PTR},
    },
    [175] = {
        .retval = INT,
        .name = "init_module",
        .args_value = {PTR, INT, STR, NONE, NONE, NONE},
    },
    [176] = {
        .retval = INT,
        .name = "delete_module",
        .args_value = {STR, INT, NONE, NONE, NONE, NONE},
    },
    [177] = {
        .retval = INT,
        .name = "get_kernel_syms",
        .args_value = {PTR, PTR, PTR, PTR, PTR, PTR},
    },
    [178] = {
        .retval = INT,
        .name = "query_module",
        .args_value = {PTR, PTR, PTR, PTR, PTR, PTR},
    },
    [179] = {
        .retval = INT,
        .name = "quotactl",
        .args_value = {INT, STR, INT, PTR, NONE, NONE},
    },
    [180] = {
        .retval = INT,
        .name = "nfsservctl",
        .args_value = {PTR, PTR, PTR, PTR, PTR, PTR},
    },
    [181] = {
        .retval = INT,
        .name = "getpmsg",
        .args_value = {PTR, PTR, PTR, PTR, PTR, PTR},
    },
    [182] = {
        .retval = INT,
        .name = "putpmsg",
        .args_value = {PTR, PTR, PTR, PTR, PTR, PTR},
    },
    [183] = {
        .retval = INT,
        .name = "afs_syscall",
        .args_value = {PTR, PTR, PTR, PTR, PTR, PTR},
    },
    [184] = {
        .retval = INT,
        .name = "tuxcall",
        .args_value = {PTR, PTR, PTR, PTR, PTR, PTR},
    },
    [185] = {
        .retval = INT,
        .name = "security",
        .args_value = {PTR, PTR, PTR, PTR, PTR, PTR},
    },
    [186] = {
        .retval = INT,
        .name = "gettid",
        .args_value = {NONE, NONE, NONE, NONE, NONE, NONE},
    },
    [187] = {
        .retval = INT,
        .name = "readahead",
        .args_value = {INT, INT, INT, NONE, NONE, NONE},
    },
    [188] = {
        .retval = INT,
        .name = "setxattr",
        .args_value = {STR, STR, PTR, INT, INT, NONE},
    },
    [189] = {
        .retval = INT,
        .name = "lsetxattr",
        .args_value = {STR, STR, PTR, INT, INT, NONE},
    },
    [190] = {
        .retval = INT,
        .name = "fsetxattr",
        .args_value = {INT, STR, PTR, INT, INT, NONE},
    },
    [191] = {
        .retval = INT,
        .name = "getxattr",
        .args_value = {STR, STR, PTR, INT, NONE, NONE},
    },
    [192] = {
        .retval = INT,
        .name = "lgetxattr",
        .args_value = {STR, STR, PTR, INT, NONE, NONE},
    },
    [193] = {
        .retval = INT,
        .name = "fgetxattr",
        .args_value = {INT, STR, PTR, INT, NONE, NONE},
    },
    [194] = {
        .retval = INT,
        .name = "listxattr",
        .args_value = {STR, STR, INT, NONE, NONE, NONE},
    },
    [195] = {
        .retval = INT,
        .name = "llistxattr",
        .args_value = {STR, STR, INT, NONE, NONE, NONE},
    },
    [196] = {
        .retval = INT,
        .name = "flistxattr",
        .args_value = {INT, STR, INT, NONE, NONE, NONE},
    },
    [197] = {
        .retval = INT,
        .name = "removexattr",
        .args_value = {STR, STR, NONE, NONE, NONE, NONE},
    },
    [198] = {
        .retval = INT,
        .name = "lremovexattr",
        .args_value = {STR, STR, NONE, NONE, NONE, NONE},
    },
    [199] = {
        .retval = INT,
        .name = "fremovexattr",
        .args_value = {INT, STR, NONE, NONE, NONE, NONE},
    },
    [200] = {
        .retval = INT,
        .name = "tkill",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [201] = {
        .retval = INT,
        .name = "time",
        .args_value = {PTR, NONE, NONE, NONE, NONE, NONE},
    },
    [202] = {
        .retval = INT,
        .name = "futex",
        .args_value = {PTR, INT, INT, PTR, PTR, INT},
    },
    [203] = {
        .retval = INT,
        .name = "sched_setaffinity",
        .args_value = {INT, INT, PTR, NONE, NONE, NONE},
    },
    [204] = {
        .retval = INT,
        .name = "sched_getaffinity",
        .args_value = {INT, INT, PTR, NONE, NONE, NONE},
    },
    [205] = {
        .retval = INT,
        .name = "set_thread_area",
        .args_value = {PTR, NONE, NONE, NONE, NONE, NONE},
    },
    [206] = {
        .retval = INT,
        .name = "io_setup",
        .args_value = {INT, PTR, NONE, NONE, NONE, NONE},
    },
    [207] = {
        .retval = INT,
        .name = "io_destroy",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [208] = {
        .retval = INT,
        .name = "io_getevents",
        .args_value = {INT, INT, INT, PTR, PTR, NONE},
    },
    [209] = {
        .retval = INT,
        .name = "io_submit",
        .args_value = {INT, INT, PTR, NONE, NONE, NONE},
    },
    [210] = {
        .retval = INT,
        .name = "io_cancel",
        .args_value = {INT, PTR, PTR, NONE, NONE, NONE},
    },
    [211] = {
        .retval = INT,
        .name = "get_thread_area",
        .args_value = {PTR, NONE, NONE, NONE, NONE, NONE},
    },
    [212] = {
        .retval = INT,
        .name = "lookup_dcookie",
        .args_value = {INT, STR, INT, NONE, NONE, NONE},
    },
    [213] = {
        .retval = INT,
        .name = "epoll_create",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [214] = {
        .retval = INT,
        .name = "epoll_ctl_old",
        .args_value = {PTR, PTR, PTR, PTR, PTR, PTR},
    },
    [215] = {
        .retval = INT,
        .name = "epoll_wait_old",
        .args_value = {PTR, PTR, PTR, PTR, PTR, PTR},
    },
    [216] = {
        .retval = INT,
        .name = "remap_file_pages",
        .args_value = {INT, INT, INT, INT, INT, NONE},
    },
    [217] = {
        .retval = INT,
        .name = "getdents64",
        .args_value = {INT, PTR, INT, NONE, NONE, NONE},
    },
    [218] = {
        .retval = INT,
        .name = "set_tid_address",
        .args_value = {PTR, NONE, NONE, NONE, NONE, NONE},
    },
    [219] = {
        .retval = INT,
        .name = "restart_syscall",
        .args_value = {NONE, NONE, NONE, NONE, NONE, NONE},
    },
    [220] = {
        .retval = INT,
        .name = "semtimedop",
        .args_value = {INT, PTR, INT, PTR, NONE, NONE},
    },
    [221] = {
        .retval = INT,
        .name = "fadvise64",
        .args_value = {INT, INT, INT, INT, NONE, NONE},
    },
    [222] = {
        .retval = INT,
        .name = "timer_create",
        .args_value = {INT, PTR, PTR, NONE, NONE, NONE},
    },
    [223] = {
        .retval = INT,
        .name = "timer_settime",
        .args_value = {INT, INT, PTR, PTR, NONE, NONE},
    },
    [224] = {
        .retval = INT,
        .name = "timer_gettime",
        .args_value = {INT, PTR, NONE, NONE, NONE, NONE},
    },
    [225] = {
        .retval = INT,
        .name = "timer_getoverrun",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [226] = {
        .retval = INT,
        .name = "timer_delete",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [227] = {
        .retval = INT,
        .name = "clock_settime",
        .args_value = {INT, PTR, NONE, NONE, NONE, NONE},
    },
    [228] = {
        .retval = INT,
        .name = "clock_gettime",
        .args_value = {INT, PTR, NONE, NONE, NONE, NONE},
    },
    [229] = {
        .retval = INT,
        .name = "clock_getres",
        .args_value = {INT, PTR, NONE, NONE, NONE, NONE},
    },
    [230] = {
        .retval = INT,
        .name = "clock_nanosleep",
        .args_value = {INT, INT, PTR, PTR, NONE, NONE},
    },
    [231] = {
        .retval = NONE,
        .name = "exit_group",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [232] = {
        .retval = INT,
        .name = "epoll_wait",
        .args_value = {INT, PTR, INT, INT, NONE, NONE},
    },
    [233] = {
        .retval = INT,
        .name = "epoll_ctl",
        .args_value = {INT, INT, INT, PTR, NONE, NONE},
    },
    [234] = {
        .retval = INT,
        .name = "tgkill",
        .args_value = {INT, INT, INT, NONE, NONE, NONE},
    },
    [235] = {
        .retval = INT,
        .name = "utimes",
        .args_value = {STR, PTR, NONE, NONE, NONE, NONE},
    },
    [236] = {
        .retval = INT,
        .name = "vserver",
        .args_value = {PTR, PTR, PTR, PTR, PTR, PTR},
    },
    [237] = {
        .retval = INT,
        .name = "mbind",
        .args_value = {INT, INT, INT, PTR, INT, INT},
    },
    [238] = {
        .retval = INT,
        .name = "set_mempolicy",
        .args_value = {INT, PTR, INT, NONE, NONE, NONE},
    },
    [239] = {
        .retval = INT,
        .name = "get_mempolicy",
        .args_value = {PTR, PTR, INT, INT, INT, NONE},
    },
    [240] = {
        .retval = INT,
        .name = "mq_open",
        .args_value = {STR, INT, INT, PTR, NONE, NONE},
    },
    [241] = {
        .retval = INT,
        .name = "mq_unlink",
        .args_value = {STR, NONE, NONE, NONE, NONE, NONE},
    },
    [242] = {
        .retval = INT,
        .name = "mq_timedsend",
        .args_value = {INT, STR, INT, INT, PTR, NONE},
    },
    [243] = {
        .retval = INT,
        .name = "mq_timedreceive",
        .args_value = {INT, STR, INT, PTR, PTR, NONE},
    },
    [244] = {
        .retval = INT,
        .name = "mq_notify",
        .args_value = {INT, PTR, NONE, NONE, NONE, NONE},
    },
    [245] = {
        .retval = INT,
        .name = "mq_getsetattr",
        .args_value = {INT, PTR, PTR, NONE, NONE, NONE},
    },
    [246] = {
        .retval = INT,
        .name = "kexec_load",
        .args_value = {INT, INT, PTR, INT, NONE, NONE},
    },
    [247] = {
        .retval = INT,
        .name = "waitid",
        .args_value = {INT, INT, PTR, INT, PTR, NONE},
    },
    [248] = {
        .retval = INT,
        .name = "add_key",
        .args_value = {STR, STR, PTR, INT, INT, NONE},
    },
    [249] = {
        .retval = INT,
        .name = "request_key",
        .args_value = {STR, STR, STR, INT, NONE, NONE},
    },
    [250] = {
        .retval = INT,
        .name = "keyctl",
        .args_value = {INT, INT, INT, INT, INT, NONE},
    },
    [251] = {
        .retval = INT,
        .name = "ioprio_set",
        .args_value = {PTR, PTR, PTR, PTR, PTR, PTR},
    },
    [252] = {
        .retval = INT,
        .name = "ioprio_get",
        .args_value = {PTR, PTR, PTR, PTR, PTR, PTR},
    },
    [253] = {
        .retval = INT,
        .name = "inotify_init",
        .args_value = {NONE, NONE, NONE, NONE, NONE, NONE},
    },
    [254] = {
        .retval = INT,
        .name = "inotify_add_watch",
        .args_value = {INT, STR, INT, NONE, NONE, NONE},
    },
    [255] = {
        .retval = INT,
        .name = "inotify_rm_watch",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [256] = {
        .retval = INT,
        .name = "migrate_pages",
        .args_value = {INT, INT, PTR, PTR, NONE, NONE},
    },
    [257] = {
        .retval = INT,
        .name = "openat",
        .args_value = {INT, STR, INT, INT, NONE, NONE},
    },
    [258] = {
        .retval = INT,
        .name = "mkdirat",
        .args_value = {INT, STR, INT, NONE, NONE, NONE},
    },
    [259] = {
        .retval = INT,
        .name = "mknodat",
        .args_value = {INT, STR, INT, INT, NONE, NONE},
    },
    [260] = {
        .retval = INT,
        .name = "fchownat",
        .args_value = {INT, STR, INT, INT, INT, NONE},
    },
    [261] = {
        .retval = INT,
        .name = "futimesat",
        .args_value = {INT, STR, PTR, NONE, NONE, NONE},
    },
    [262] = {
        .retval = INT,
        .name = "newfstatat",
        .args_value = {INT, STR, PTR, INT, NONE, NONE},
    },
    [263] = {
        .retval = INT,
        .name = "unlinkat",
        .args_value = {INT, STR, INT, NONE, NONE, NONE},
    },
    [264] = {
        .retval = INT,
        .name = "renameat",
        .args_value = {INT, STR, INT, STR, NONE, NONE},
    },
    [265] = {
        .retval = INT,
        .name = "linkat",
        .args_value = {INT, STR, INT, STR, INT, NONE},
    },
    [266] = {
        .retval = INT,
        .name = "symlinkat",
        .args_value = {STR, INT, STR, NONE, NONE, NONE},
    },
    [267] = {
        .retval = INT,
        .name = "readlinkat",
        .args_value = {INT, STR, STR, INT, NONE, NONE},
    },
    [268] = {
        .retval = INT,
        .name = "fchmodat",
        .args_value = {INT, STR, INT, NONE, NONE, NONE},
    },
    [269] = {
        .retval = INT,
        .name = "faccessat",
        .args_value = {INT, STR, INT, NONE, NONE, NONE},
    },
    [270] = {
        .retval = INT,
        .name = "pselect6",
        .args_value = {INT, PTR, PTR, PTR, PTR, PTR},
    },
    [271] = {
        .retval = INT,
        .name = "ppoll",
        .args_value = {PTR, INT, PTR, PTR, INT, NONE},
    },
    [272] = {
        .retval = INT,
        .name = "unshare",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [273] = {
        .retval = INT,
        .name = "set_robust_list",
        .args_value = {PTR, INT, NONE, NONE, NONE, NONE},
    },
    [274] = {
        .retval = INT,
        .name = "get_robust_list",
        .args_value = {INT, PTR, PTR, NONE, NONE, NONE},
    },
    [275] = {
        .retval = INT,
        .name = "splice",
        .args_value = {INT, PTR, INT, PTR, INT, INT},
    },
    [276] = {
        .retval = INT,
        .name = "tee",
        .args_value = {INT, INT, INT, INT, NONE, NONE},
    },
    [277] = {
        .retval = INT,
        .name = "sync_file_range",
        .args_value = {INT, INT, INT, INT, NONE, NONE},
    },
    [278] = {
        .retval = INT,
        .name = "vmsplice",
        .args_value = {INT, PTR, INT, INT, NONE, NONE},
    },
    [279] = {
        .retval = INT,
        .name = "move_pages",
        .args_value = {INT, INT, PTR, PTR, PTR, INT},
    },
    [280] = {
        .retval = INT,
        .name = "utimensat",
        .args_value = {INT, STR, PTR, INT, NONE, NONE},
    },
    [281] = {
        .retval = INT,
        .name = "epoll_pwait",
        .args_value = {INT, PTR, INT, INT, PTR, INT},
    },
    [282] = {
        .retval = INT,
        .name = "signalfd",
        .args_value = {INT, PTR, INT, NONE, NONE, NONE},
    },
    [283] = {
        .retval = INT,
        .name = "timerfd_create",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [284] = {
        .retval = INT,
        .name = "eventfd",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [285] = {
        .retval = INT,
        .name = "fallocate",
        .args_value = {INT, INT, INT, INT, NONE, NONE},
    },
    [286] = {
        .retval = INT,
        .name = "timerfd_settime",
        .args_value = {INT, INT, PTR, PTR, NONE, NONE},
    },
    [287] = {
        .retval = INT,
        .name = "timerfd_gettime",
        .args_value = {INT, PTR, NONE, NONE, NONE, NONE},
    },
    [288] = {
        .retval = INT,
        .name = "accept4",
        .args_value = {INT, PTR, PTR, INT, NONE, NONE},
    },
    [289] = {
        .retval = INT,
        .name = "signalfd4",
        .args_value = {INT, PTR, INT, INT, NONE, NONE},
    },
    [290] = {
        .retval = INT,
        .name = "eventfd2",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [291] = {
        .retval = INT,
        .name = "epoll_create1",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [292] = {
        .retval = INT,
        .name = "dup3",
        .args_value = {INT, INT, INT, NONE, NONE, NONE},
    },
    [293] = {
        .retval = INT,
        .name = "pipe2",
        .args_value = {PTR, INT, NONE, NONE, NONE, NONE},
    },
    [294] = {
        .retval = INT,
        .name = "inotify_init1",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [295] = {
        .retval = INT,
        .name = "preadv",
        .args_value = {INT, PTR, INT, INT, INT, NONE},
    },
    [296] = {
        .retval = INT,
        .name = "pwritev",
        .args_value = {INT, PTR, INT, INT, INT, NONE},
    },
    [297] = {
        .retval = INT,
        .name = "rt_tgsigqueueinfo",
        .args_value = {INT, INT, INT, PTR, NONE, NONE},
    },
    [298] = {
        .retval = INT,
        .name = "perf_event_open",
        .args_value = {PTR, INT, INT, INT, INT, NONE},
    },
    [299] = {
        .retval = INT,
        .name = "recvmmsg",
        .args_value = {INT, PTR, INT, INT, PTR, NONE},
    },
    [300] = {
        .retval = INT,
        .name = "fanotify_init",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [301] = {
        .retval = INT,
        .name = "fanotify_mark",
        .args_value = {INT, INT, INT, INT, STR, NONE},
    },
    [302] = {
        .retval = INT,
        .name = "prlimit64",
        .args_value = {INT, INT, PTR, PTR, NONE, NONE},
    },
    [303] = {
        .retval = INT,
        .name = "name_to_handle_at",
        .args_value = {INT, STR, PTR, PTR, INT, NONE},
    },
    [304] = {
        .retval = INT,
        .name = "open_by_handle_at",
        .args_value = {INT, PTR, INT, NONE, NONE, NONE},
    },
    [305] = {
        .retval = INT,
        .name = "clock_adjtime",
        .args_value = {INT, PTR, NONE, NONE, NONE, NONE},
    },
    [306] = {
        .retval = INT,
        .name = "syncfs",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [307] = {
        .retval = INT,
        .name = "sendmmsg",
        .args_value = {INT, PTR, INT, INT, NONE, NONE},
    },
    [308] = {
        .retval = INT,
        .name = "setns",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [309] = {
        .retval = INT,
        .name = "getcpu",
        .args_value = {PTR, PTR, PTR, NONE, NONE, NONE},
    },
    [310] = {
        .retval = INT,
        .name = "process_vm_readv",
        .args_value = {INT, PTR, INT, PTR, INT, INT},
    },
    [311] = {
        .retval = INT,
        .name = "process_vm_writev",
        .args_value = {INT, PTR, INT, PTR, INT, INT},
    },
    [312] = {
        .retval = INT,
        .name = "kcmp",
        .args_value = {INT, INT, INT, INT, INT, NONE},
    },
    [313] = {
        .retval = INT,
        .name = "finit_module",
        .args_value = {INT, STR, INT, NONE, NONE, NONE},
    },
    [314] = {
        .retval = INT,
        .name = "sched_setattr",
        .args_value = {INT, PTR, INT, NONE, NONE, NONE},
    },
    [315] = {
        .retval = INT,
        .name = "sched_getattr",
        .args_value = {INT, PTR, INT, INT, NONE, NONE},
    },
    [316] = {
        .retval = INT,
        .name = "renameat2",
        .args_value = {INT, STR, INT, STR, INT, NONE},
    },
    [317] = {
        .retval = INT,
        .name = "seccomp",
        .args_value = {INT, INT, STR, NONE, NONE, NONE},
    },
    [318] = {
        .retval = INT,
        .name = "getrandom",
        .args_value = {PTR, PTR, PTR, PTR, PTR, PTR},
    },
    [319] = {
        .retval = INT,
        .name = "memfd_create",
        .args_value = {STR, INT, NONE, NONE, NONE, NONE},
    },
    [320] = {
        .retval = INT,
        .name = "kexec_file_load",
        .args_value = {INT, INT, INT, STR, INT, NONE},
    },
    [321] = {
        .retval = INT,
        .name = "bpf",
        .args_value = {INT, PTR, INT, NONE, NONE, NONE},
    },
    [322] = {
        .retval = INT,
        .name = "execveat",
        .args_value = {INT, STR, PTR, PTR, INT, NONE},
    },
    [323] = {
        .retval = INT,
        .name = "userfaultfd",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [324] = {
        .retval = INT,
        .name = "membarrier",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [325] = {
        .retval = INT,
        .name = "mlock2",
        .args_value = {INT, INT, INT, NONE, NONE, NONE},
    },
    [326] = {
        .retval = INT,
        .name = "copy_file_range",
        .args_value = {INT, PTR, INT, PTR, INT, INT},
    },
    [327] = {
        .retval = INT,
        .name = "preadv2",
        .args_value = {INT, PTR, INT, INT, INT, INT},
    },
    [328] = {
        .retval = INT,
        .name = "pwritev2",
        .args_value = {INT, PTR, INT, INT, INT, INT},
    },
    [329] = {
        .retval = INT,
        .name = "pkey_mprotect",
        .args_value = {INT, INT, INT, INT, NONE, NONE},
    },
    [330] = {
        .retval = INT,
        .name = "pkey_alloc",
        .args_value = {INT, INT, NONE, NONE, NONE, NONE},
    },
    [331] = {
        .retval = INT,
        .name = "pkey_free",
        .args_value = {INT, NONE, NONE, NONE, NONE, NONE},
    },
    [332] = {
        .retval = INT,
        .name = "statx",
        .args_value = {INT, STR, INT, INT, PTR, NONE},
    },
    [333] = {
        .retval = INT,
        .name = "io_pgetevents",
        .args_value = {PTR, INT, INT, PTR, PTR, PTR},
    },
    [334] = {
        .retval = INT,
        .name = "rseq",
        .args_value = {PTR, PTR, INT, PTR, NONE, NONE},
    }
};
