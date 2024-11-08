/*
** EPITECH PROJECT, 2024
** ftrace.h
** File description:
** ftrace.h.
*/

#pragma once

#include <libelf.h>
#include <stdint.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "memory_map.h"

typedef struct {
    Elf64_Shdr *shdr;
    Elf64_Sym *symtab;
    uint64_t sym_count;
} section_table_t;

typedef struct {
    char fct_stack[4096][256];
    uint8_t len;
} function_stack_t;

extern function_stack_t fct_stack;

#define CALL_INSTRUCTION_SIZE 5
#define CALL_NEAR_RELATIVE 0xe8
#define GET_MOD(modrm) (((modrm) >> 6) & 0x03)
#define GET_REG(modrm) (((modrm) >> 3) & 0x07)
#define GET_RM(modrm)  ((modrm) & 0x07)
#define GET_SCALE(sib) ((sib >> 6) & 0x3)
#define GET_INDEX(sib) ((sib >> 3) & 0x7)
#define GET_BASE(sib)  (sib & 0x7)
#define ASSIGN(var, val) var EQUAL val
#define SCASE(val, line) case val COLON line SEMICOLON

// Strace
void ftrace_command(char **args, char **env);

// Get information about registers
uint64_t get_register(struct user_regs_struct const *regs, uint8_t arg);

// Print utils functions
void print_syscall(const struct user_regs_struct *regs);
void print_ret(unsigned long long syscall, unsigned long long return_value);
void print_entering_function(const char *function_name, int64_t len,
    uint64_t ptr);
void print_leaving_function(const char *function_name, int64_t len);

// Signal handling
void write_signal(int signal);

// Elf utils functions
uint8_t verify_elf(Elf *elf);
char *get_symbol_from_address(Elf *elf, const section_table_t *symbol_table,
    uint64_t address);
uint8_t load_elf_file(memory_map_t *memory_map);

// Call analysis
uint64_t get_near_relative_function(unsigned char *instruction_bytes,
    const struct user_regs_struct *regs);
uint64_t get_near_absolute_function(const unsigned char *ins_bytes,
    const struct user_regs_struct *regs, pid_t pid);
void create_function_name(memory_map_array_t **maps,
    const pid_t pid,
    const unsigned long call_address,
    const char *tracee_bin_name);
