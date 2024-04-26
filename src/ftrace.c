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
#include "memory_map.h"

memory_map_array_t *memory_map_array;

static void check_err(int64_t ret, char const *msg)
{
    if (ret == -1) {
        perror(msg);
        _exit(84);
    }
}

static void trace_exit_call(pid_t pid, struct user_regs_struct *regs)
{
    check_err(ptrace(PTRACE_GETREGS, pid, NULL, regs), "ptrace: getregs");
    if ((*regs).orig_rax <= 334) {
        print_syscall(regs);
        print_ret((*regs).orig_rax, regs->rax);
    }
}

static void handle_signal(int status)
{
    int sig;

    if (WIFSTOPPED(status)) {
        sig = WSTOPSIG(status);
        if (sig != 5) {
            write(1, "Received signal ", 16);
            write_signal(sig);
            write(1, "\n", 1);
        }
    }
}

static void trace_syscall(const pid_t pid,
    struct user_regs_struct *regs,
    int *status)
{
    unsigned long long syscall = regs->orig_rax;

    print_syscall(regs);
    check_err(ptrace(PTRACE_SINGLESTEP, pid, 0, 0), "ptrace: singlestep");
    waitpid(pid, status, 0);
    check_err(ptrace(PTRACE_GETREGS, pid, NULL, regs), "ptrace: getregs");
    print_ret(syscall, regs->rax);
}

static void trace_call(const pid_t pid,
    struct user_regs_struct *regs,
    int *status)
{
    long instruction;
    unsigned char *instruction_bytes;

    ptrace(PTRACE_GETREGS, pid, NULL, regs);
    instruction = ptrace(PTRACE_PEEKTEXT, pid, regs->rip, NULL);
    instruction_bytes = (unsigned char *)&instruction;
    handle_signal(*status);
    if (regs->orig_rax <= 334)
        return trace_syscall(pid, regs, status);
    if (instruction_bytes[0] == CALL_NEAR_RELATIVE)
        get_near_relative_function(instruction_bytes, regs);
    if (instruction_bytes[0] == 0xFF && GET_REG(instruction_bytes[1]) == 2)
        get_near_absolute_function(instruction_bytes, regs, pid);
    check_err(ptrace(PTRACE_SINGLESTEP, pid, 0, 0), "ptrace: singlestep");
    waitpid(pid, status, 0);
}

static void trace_process(pid_t pid)
{
    struct user_regs_struct regs;
    int status;
    uint8_t exit_status;

    memory_map_array_t *sex = get_memory_maps(pid);
    printf("premier : %s\n", sex->memory_maps[0].filename);
    waitpid(pid, &status, 0);
    ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACEEXIT);
    while (status >> 8 != (SIGTRAP | (PTRACE_EVENT_EXIT << 8)))
        trace_call(pid, &regs, &status);
    trace_exit_call(pid, &regs);
    check_err(ptrace(PTRACE_GETEVENTMSG, pid, NULL, &exit_status),
    "ptrace: geteventmsg");
    check_err(ptrace(PTRACE_DETACH, pid, NULL, NULL), "ptrace: detach");
}

void ftrace_command(char **args, char **env)
{
    pid_t tracee = fork();

    if (tracee == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execve(args[1], args, env);
        _exit(0);
    }
    trace_process(tracee);
}
