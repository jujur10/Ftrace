/*
** EPITECH PROJECT, 2024
** main.c
** File description:
** Main file
*/
#include <unistd.h>
#include <string.h>
#include "ftrace.h"

int print_help(void)
{
    write(1, "USAGE: ftrace <command>\n", 24);
    return 0;
}

int main(int argc, char *argv[], char **env)
{
    if (argc == 2 && 0 == strncmp(argv[1], "--help", 6))
        return print_help();
    if (argc != 2)
        return 84;
    strace_command(argv, env);
    return 0;
}
