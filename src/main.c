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

int print_help(void)
{
    write(1, "USAGE: ftrace <command>\n", 24);
    return 0;
}

int main(int argc, char *argv[], char **env)
{
    int fd;
    Elf *elf;
    symbol_table_t symbol_table = INIT_SYMBOL_TABLE;

    elf_version(EV_CURRENT);
    if (argc == 2 && 0 == strncmp(argv[1], "--help", 6))
        return print_help();
    if (argc < 2)
        return 84;
    fd = open(argv[1], O_RDONLY);
    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (verify_elf(elf) == 1) {
        elf_end(elf);
        close(fd);
        return 84;
    }
    if (1 == get_symbol_table(elf, &symbol_table)) {
        elf_end(elf);
        close(fd);
        return 84;
    }
    ftrace_command(argv, env);
    get_symbol_from_address(elf, &symbol_table, 1139);
    elf_end(elf);
    close(fd);
    return 0;
}
