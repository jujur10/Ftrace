/*
** EPITECH PROJECT, 2024
** call_near_relative.c
** File description:
** e8 op code functions
*/

#include <ftrace.h>
#include <stdio.h>
#include <unistd.h>

void analyse_near_relative_function(unsigned char *instruction_bytes,
    const struct user_regs_struct *regs)
{
    const int32_t relative_displacement = *(int32_t *)(instruction_bytes + 1);
    const uint64_t target_address = regs->rip + relative_displacement +
        CALL_INSTRUCTION_SIZE;
    char buffer[64] = {};
    const int32_t len = snprintf(buffer, 64, "Function call at %#lx\n",
    target_address);

    write(1, buffer, len);
}
