/*
** EPITECH PROJECT, 2024
** memory_map_utils.c
** File description:
** memory_map_utils.c.
*/
#include "map.h"
#include <stdio.h>

static uint64_t get_virtual_address_start(pid_t pid)
{
    FILE *fp;
    uint64_t base_address = 0;
    char line[256];
    char path[200] = {};
    uint64_t start;
    uint64_t end;
    uint32_t offset;
    char perms[5];
    char filename[500] = {};

    snprintf(path, 200, "/proc/%i/maps", pid);
    fp = fopen(path, "r");
    if (NULL == fp)
        return 0;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%lx-%lx %4s %x %x:%x %u %[^\\n]", &start, &end,
                   perms, &offset, NULL, NULL, NULL, filename) ==
        3 &&
            perms[2] == 'x') {
            base_address = start;
            break;
        }
    }
    return close_and_return(fp, base_address);
}
