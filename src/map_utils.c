/*
** EPITECH PROJECT, 2024
** map_utils.c
** File description:
** map_utils.c.
*/
#include <libelf.h>
#include <stdlib.h>

#include "ftrace.h"
#include "map.h"

void create_map_from_section_table(Elf *elf,
    const section_table_t *section_table, map_t *map)
{
    const Elf64_Shdr *shdr = section_table->shdr;
    const Elf64_Sym *symtab = section_table->symtab;
    uint64_t sym_count = section_table->sym_count;

    map->keys = calloc(sym_count, sizeof(uint64_t));
    map->values = calloc(sym_count, sizeof(char *));
    map->len = sym_count;
    for (uint64_t i = 0; i < sym_count; ++i) {
        map->keys[i] = symtab[i].st_value;
        map->values[i] = elf_strptr(elf, shdr->sh_link, symtab[i].st_name);
    }
}

const char *get_value_from_key(const map_t *map, uint64_t key)
{
    for (uint64_t i = 0; i < map->len; i++)
        if (map->keys[i] == key)
            return map->values[i];
    return NULL;
}

void destroy_map(map_t *map)
{
    free(map->keys);
    free(map->values);
}
