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
#include "map.h"

map_t *maps = NULL;

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

static void free_and_close_everything(Elf *elf)
{
    if (elf != NULL)
        elf_end(elf);
    destroy_map(&symbol_table_map);
    destroy_map(&dynamic_symbol_map);
}

static uint8_t create_maps(Elf *elf)
{
    section_table_t symbol_table = {NULL, NULL, 0};
    section_table_t dynamic_symbol = {NULL, NULL, 0};

    if (1 == get_section_tables(elf, &symbol_table, &dynamic_symbol))
        return 1;
    create_map_from_section_table(elf, &symbol_table, &symbol_table_map);
    create_map_from_section_table(elf, &dynamic_symbol, &dynamic_symbol_map);
    return 0;
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
    create_maps(elf);
    ftrace_command(argv, env);
    free_and_close_everything(elf);
    return 0;
}
