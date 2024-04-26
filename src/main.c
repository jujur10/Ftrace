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

function_stack_t fct_stack;

static int print_help(void)
{
    write(1, "USAGE: ftrace <command>\n", 24);
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
    memset(&fct_stack, 0, sizeof(function_stack_t));
    ftrace_command(argv, env);
    return 0;
}
