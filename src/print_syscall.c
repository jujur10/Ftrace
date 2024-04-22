/*
** EPITECH PROJECT, 2024
** print_syscall.c
** File description:
** print_syscall.c.
*/
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/user.h>

#include "syscalls.h"
#include "ftrace.h"

void print_ret(unsigned long long syscall, unsigned long long return_value)
{
    char buffer[20];
    int32_t len;

    if (syscalls[syscall].retval == NONE)
        write(1, "?\n", 2);
    else {
        len = snprintf(buffer, 20, "0x%lx\n", (int64_t)return_value);
        write(1, buffer, len);
    }
}

void print_syscall(const struct user_regs_struct *regs)
{
    const syscall_t current_syscall = syscalls[regs->orig_rax];
    char buffer[20] = {};
    int32_t len;

    write(1, "Syscall ", 8);
    write(1, current_syscall.name, strlen(current_syscall.name));
    write(1, " (", 2);
    for (uint8_t i = 0; i < 6 && current_syscall.args_value[i] != NONE; i++) {
        len = snprintf(buffer, 20, "0x%lx", get_register(regs, i));
        write(1, buffer, len);
        if ((i + 1) < 6 && current_syscall.args_value[i + 1] != NONE)
            write(1, ", ", 2);
    }
    write(1, ") = ", 4);
}
