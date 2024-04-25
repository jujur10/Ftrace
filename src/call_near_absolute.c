/*
** EPITECH PROJECT, 2024
** call_near_absolute.c
** File description:
** ff op code functions
*/

#include "ftrace.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>

static uint64_t get_index(const struct user_regs_struct *regs,
    const unsigned char sib)
{
    switch (GET_INDEX(sib)) {
        case 0:
            return regs->rax;
        case 1:
            return regs->rcx;
        case 2:
            return regs->rdx;
        case 3:
            return regs->rbx;
        case 4:
            return 0;
        case 5:
            return regs->rbp;
        case 6:
            return regs->rsi;
        case 7:
            return regs->rdi;
    }
    return 0;
}

static uint64_t get_base(const unsigned char *instruction_bytes,
    const struct user_regs_struct *regs,
    const unsigned char sib,
    const uint8_t mod)
{
    switch (GET_BASE(sib)) {
        case 0:
            return regs->rax;
        case 1:
            return regs->rcx;
        case 2:
            return regs->rdx;
        case 3:
            return regs->rbx;
        case 4:
            return regs->rsp;
        case 5:
            if (mod == 0)
                return *(uint32_t *)(instruction_bytes + 3);
            return regs->rbp;
        case 6:
            return regs->rsi;
        case 7:
            return regs->rdi;
    }
    return 0;
}

static uint64_t get_sib(const unsigned char *instruction_bytes,
                        const struct user_regs_struct *regs)
{
    const unsigned char sib = instruction_bytes[2];
    const uint8_t mod = GET_MOD(instruction_bytes[0]);
    const uint64_t index = get_index(regs, sib);
    const uint64_t scale = 1 << GET_SCALE(sib);
    const uint64_t base = get_base(instruction_bytes, regs, sib, mod);

    write(1, "sib\n", 4);
    return base + index * scale;
}

static uint64_t analyse_mod0(const unsigned char *ins_bytes,
    const struct user_regs_struct *regs, pid_t pid)
{
    write(1, "mod0\n", 5);
    switch (GET_RM(ins_bytes[1])) {
        SCASE(0, return ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rax, NULL))
        SCASE(1, return ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rcx, NULL))
        SCASE(2, return ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rdx, NULL))
        SCASE(3, return ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rbx, NULL))
        SCASE(4, return ptrace(PTRACE_PEEKDATA, pid, (void*)get_sib(ins_bytes, regs), NULL))
        SCASE(5, return ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rip +
            *(int32_t *)(ins_bytes + 2), NULL))
        SCASE(6, return ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rsi, NULL))
        SCASE(7, return ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rdi, NULL))
    }
    return 0;
}

static uint64_t analyse_mod1(const unsigned char *ins_bytes,
    const struct user_regs_struct *regs, pid_t pid)
{
    write(1, "mod1\n", 5);
    switch (GET_RM(ins_bytes[1])) {
        SCASE(0, return ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rax +
            *(int8_t *)(ins_bytes + 2), NULL))
        SCASE(1, return ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rcx +
            *(int8_t *)(ins_bytes + 2), NULL))
        SCASE(2, return ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rdx +
            *(int8_t *)(ins_bytes + 2), NULL))
        SCASE(3, return ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rbx +
            *(int8_t *)(ins_bytes + 2), NULL))
        SCASE(4, return ptrace(PTRACE_PEEKDATA, pid,
            (void*)get_sib(ins_bytes, regs) + *(int8_t *)(ins_bytes + 3)))
        SCASE(5, return ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rbp +
            *(int8_t *)(ins_bytes + 2), NULL))
        SCASE(6, return ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rsi +
            *(int8_t *)(ins_bytes + 2), NULL))
        SCASE(7, return ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rdi +
            *(int8_t *)(ins_bytes + 2), NULL))
    }
    return 0;
}

static uint64_t analyse_mod2(const unsigned char *ins_bytes,
    const struct user_regs_struct *regs, pid_t pid)
{
    write(1, "mod2\n", 5);
    switch (GET_RM(ins_bytes[1])) {
        SCASE(0, return ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rax +
            *(int32_t *)(ins_bytes + 2), NULL))
        SCASE(1, return ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rcx +
            *(int32_t *)(ins_bytes + 2), NULL))
        SCASE(2, return ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rdx +
            *(int32_t *)(ins_bytes + 2), NULL))
        SCASE(3, return ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rbx +
            *(int32_t *)(ins_bytes + 2), NULL))
        SCASE(4, return ptrace(PTRACE_PEEKDATA, pid,
            (void*)get_sib(ins_bytes, regs) + *(int32_t *)(ins_bytes + 3)))
        SCASE(5, return ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rbp +
            *(int32_t *)(ins_bytes + 2), NULL))
        SCASE(6, return ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rsi +
            *(int32_t *)(ins_bytes + 2), NULL))
        SCASE(7, return ptrace(PTRACE_PEEKDATA, pid, (void*)regs->rdi +
            *(int32_t *)(ins_bytes + 2), NULL))
    }
    return 0;
}

static uint64_t analyse_mod3(const unsigned char *ins_bytes,
    const struct user_regs_struct *regs)
{
    write(1, "mod3\n", 5);
    switch (GET_RM(ins_bytes[1])) {
        SCASE(0, return regs->rax)
        SCASE(1, return regs->rcx)
        SCASE(2, return regs->rdx)
        SCASE(3, return regs->rbx)
        SCASE(4, return regs->rsp)
        SCASE(5, return regs->rbp)
        SCASE(6, return regs->rsi)
        SCASE(7, return regs->rdi)
    }
    return 0;
}

void analyse_near_absolute_function(const unsigned char *ins_bytes,
    const struct user_regs_struct *regs, pid_t pid)
{
    uint64_t t_adr = 0;
    char buffer[64] = {};
    int32_t len;

    switch (GET_MOD(ins_bytes[1])) {
        case 0:
            t_adr = analyse_mod0(ins_bytes, regs, pid); BREAK
        case 1:
            t_adr = analyse_mod1(ins_bytes, regs, pid); BREAK
        case 2:
            t_adr = analyse_mod2(ins_bytes, regs, pid); BREAK
        case 3:
            t_adr = analyse_mod3(ins_bytes, regs); BREAK
    }
    len = snprintf(buffer, 64, "Function call abs at %#lx\n", t_adr);
    write(1, buffer, len);
}
