/*
** EPITECH PROJECT, 2024
** print_utils.c
** File description:
** print_utils.c.
*/
#include <sys/user.h>
#include <stdint.h>

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
