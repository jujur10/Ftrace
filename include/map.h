/*
** EPITECH PROJECT, 2024
** map.h
** File description:
** map.h.
*/

#pragma once

#include "ftrace.h"

typedef struct map_s {
    uint64_t *keys;
    char **values;
    uint64_t len;
} map_t;

// Map utils functions
void create_map_from_section_table(Elf *elf,
    const section_table_t *section_table, map_t *map);
const char *get_value_from_key(const map_t *map, uint64_t key);
void destroy_map(map_t *map);
