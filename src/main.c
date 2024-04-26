/*
** EPITECH PROJECT, 2024
** main.c
** File description:
** Main file
*/
#include <unistd.h>
#include <string.h>
#include <libelf.h>
#include <fcntl.h>

#include "ftrace.h"

static int print_help(void)
{
    write(1, "USAGE: ftrace <command>\n", 24);
    return 0;
}

static uint8_t get_section_tables(Elf *elf, section_table_t *symbol_table,
    section_table_t *dynamic_symbol)
{
    if (1 == get_section_table(elf, symbol_table, SHT_SYMTAB))
        return 1;
    if (1 == get_section_table(elf, dynamic_symbol, SHT_DYNSYM))
        return 1;
    return 0;
}

static uint8_t return_failure(int fd, Elf *elf)
{
    elf_end(elf);
    close(fd);
    return 84;
}

int main(int argc, char *argv[], char **env)
{
    int fd;
    Elf *elf;

    elf_version(EV_CURRENT);
    if (argc == 2 && 0 == strncmp(argv[1], "--help", 6))
        return print_help();
    if (argc < 2)
        return 84;
    fd = open(argv[1], O_RDONLY);
    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (1 == verify_elf(elf))
        return return_failure(fd, elf);
    elf_end(elf);
    close(fd);
    ftrace_command(argv, env);
    return 0;
}
