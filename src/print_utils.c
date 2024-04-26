/*
** EPITECH PROJECT, 2024
** print_utils.c
** File description:
** print_utils.c.
*/
#include <sys/user.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>

#include "ftrace.h"

void print_entering_function(const char *function_name, const int64_t len,
    const uint64_t ptr)
{
    char ptr_as_str[20] = {};
    int64_t ptr_len = snprintf(ptr_as_str, 20, "0x%lx", ptr);

    write(2, "Entering function ", 18);
    write(2, function_name, len);
    write(2, " at ", 4);
    write(2, ptr_as_str, ptr_len);
    write(2, "\n", 1);
}

void print_leaving_function(const char *function_name, int64_t len)
{
    write(2, "Leaving function ", 17);
    write(2, function_name, len);
    write(2, "\n", 1);
}

uint64_t get_register(struct user_regs_struct const *regs, uint8_t arg)
{
    switch (arg) {
        case 0:
            return (uint64_t)regs->rdi;
        case 1:
            return (uint64_t)regs->rsi;
        case 2:
            return (uint64_t)regs->rdx;
        case 3:
            return (uint64_t)regs->r10;
        case 4:
            return (uint64_t)regs->r8;
        case 5:
            return (uint64_t)regs->r9;
        default:
            return 0;
    }
}
