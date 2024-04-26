/*
** EPITECH PROJECT, 2024
** find_library.c
** File description:
** functions to find libraries by different methods
*/

#include <stddef.h>

#include "memory_map.h"

memory_map_t *find_symbol_lib_by_address(const memory_map_array_t *maps,
    const unsigned long addr)
{
    int64_t inode_id = -1;

    if (maps == NULL || maps->len <= 0)
        return NULL;
    for (size_t i = 0; i < maps->len; i++) {
        if (addr >= maps->memory_maps[i].start &&
        addr <= maps->memory_maps[i].end) {
            inode_id = maps->memory_maps[i].inode_id;
            break;
        }
    }
    if (-1 == inode_id)
        return NULL;
    for (size_t i = 0; i < maps->len; i++) {
        if (maps->memory_maps[i].offset == 0 && inode_id ==
        maps->memory_maps[i].inode_id) {
            return &maps->memory_maps[i];
        }
    }
    return NULL;
}
