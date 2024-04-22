/*
** EPITECH PROJECT, 2024
** main.c
** File description:
** Main file
*/
#include <unistd.h>
#include <string.h>

int print_help(void)
{
    write(1, "USAGE: ftrace <command>\n", 24);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc == 2 && 0 == strncmp(argv[1], "--help", 6))
        return print_help();
    return 84;
}
