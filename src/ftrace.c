/*
** EPITECH PROJECT, 2024
** ftrace.c
** File description:
** ftrace.c.
*/
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include "ftrace.h"

static void print_exit(uint8_t exit_code)
{
    char number_as_str[4] = {};

    snprintf(number_as_str, 4, "%hu", exit_code);
    write(1, "+++ exited with ", 16);
    write(1, number_as_str, 4);
    write(1, " +++\n", 5);
}

static void check_err(int64_t ret, char const *msg)
{
    if (ret == -1) {
        perror(msg);
        _exit(84);
    }
}

static void setup_tracing(pid_t pid, int *status)
{
    waitpid(pid, status, 0);
    ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACEEXIT);
}

void print_return(unsigned long long syscall,
    struct user_regs_struct const *regs)
{
    print_ret(syscall, regs->rax);
}

static void trace_exit_call(pid_t pid, struct user_regs_struct *regs)
{
    check_err(ptrace(PTRACE_GETREGS, pid, NULL, regs), "ptrace: getregs");
    if ((*regs).orig_rax <= 331) {
        print_syscall(regs);
        print_return((*regs).orig_rax, regs);
    }
}

static void trace_call(pid_t pid, struct user_regs_struct *regs, int *status)
{
    unsigned long long syscall;

    ptrace(PTRACE_GETREGS, pid, NULL, regs);
    syscall = (*regs).orig_rax;
    if (syscall <= 331) {
        print_syscall(regs);
        check_err(ptrace(PTRACE_SINGLESTEP, pid, 0, 0), "ptrace: singlestep");
        waitpid(pid, status, 0);
        check_err(ptrace(PTRACE_GETREGS, pid, NULL, regs), "ptrace: getregs");
        print_return(syscall, regs);
    } else {
        check_err(ptrace(PTRACE_SINGLESTEP, pid, 0, 0), "ptrace: singlestep");
        waitpid(pid, status, 0);
    }
}

static void trace_process(pid_t pid)
{
    struct user_regs_struct regs;
    int status;
    uint8_t exit_status;

    setup_tracing(pid, &status);
    while (status >> 8 != (SIGTRAP | (PTRACE_EVENT_EXIT << 8)))
        trace_call(pid, &regs, &status);
    trace_exit_call(pid, &regs);
    check_err(ptrace(PTRACE_GETEVENTMSG, pid, NULL, &exit_status),
    "ptrace: geteventmsg");
    check_err(ptrace(PTRACE_DETACH, pid, NULL, NULL), "ptrace: detach");
    print_exit(exit_status);
    _exit(exit_status);
}

void strace_command(char **args, char **env)
{
    pid_t tracee = fork();

    if (tracee == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execve(args[0], args, env);
        return;
    }
    trace_process(tracee);
}
