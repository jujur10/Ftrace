/*
** EPITECH PROJECT, 2024
** ftrace.h
** File description:
** ftrace.h.
*/

#pragma once

#include <stdint.h>
#include <semaphore.h>
#include <sys/user.h>

// Strace
void strace_command(char **args, char **env);

// Get information about registers
uint64_t get_register(struct user_regs_struct const *regs, uint8_t arg);

// Print utils functions
void print_syscall(const struct user_regs_struct *regs);
void print_ret(unsigned long long syscall, unsigned long long return_value);

// Signal handling
void write_signal(int signal);
