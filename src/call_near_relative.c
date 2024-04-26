/*
** EPITECH PROJECT, 2024
** call_near_relative.c
** File description:
** e8 op code functions
*/

#include "ftrace.h"

uint64_t get_near_relative_function(unsigned char *instruction_bytes,
    const struct user_regs_struct *regs)
{
    const int32_t relative_displacement = *(int32_t *)(instruction_bytes + 1);

    return regs->rip + relative_displacement + CALL_INSTRUCTION_SIZE;
}
