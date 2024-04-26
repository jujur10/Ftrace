/*
** EPITECH PROJECT, 2024
** find_library.c
** File description:
** functions to find libraries by different methods
*/

#include <stddef.h>
#include <string.h>

#include "memory_map.h"

memory_map_t *find_symbol_lib_by_address(const memory_map_array_t *maps,
    const unsigned long addr)
{
    char *lib_name_that_contain_fct = NULL;

    if (maps == NULL || maps->len <= 0)
        return NULL;
    for (size_t i = 0; i < maps->len; i++) {
        if (addr >= maps->memory_maps[i].start &&
        addr <= maps->memory_maps[i].end) {
            lib_name_that_contain_fct = maps->memory_maps[i].filename;
            break;
        }
    }
    if (lib_name_that_contain_fct == NULL)
        return NULL;
    for (size_t i = 0; i < maps->len; i++) {
        if (maps->memory_maps[i].offset == 0 &&
        strcmp(lib_name_that_contain_fct, maps->memory_maps[i].filename)) {
            return &maps->memory_maps[i];
        }
    }
    return NULL;
}
