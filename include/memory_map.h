/*
** EPITECH PROJECT, 2024
** memory_map.h
** File description:
** memory_map.h.
*/

#pragma once

#include <elf.h>
#include <gelf.h>

typedef struct elf_file_s {
    int fd;
    Elf *elf;
    GElf_Shdr *sym_shdr;
    Elf_Data *sym_data;
    GElf_Shdr *plt_shdr;
    Elf_Data *plt_data;
    GElf_Shdr *dyn_shdr;
    Elf_Data *dyn_data;
} elf_file_t;

typedef struct memory_map_s {
    uint64_t start;
    uint64_t end;
    uint32_t offset;
    uint32_t inode_id;
    char *filename;
    elf_file_t elf_file;
    uint8_t is_pie;
} memory_map_t;

typedef struct memory_map_array_s {
    memory_map_t *memory_maps;
    uint64_t len;
} memory_map_array_t;

extern memory_map_array_t *memory_map_array;

// Memory map function
memory_map_array_t *get_memory_maps(pid_t pid);

void destroy_memory_maps(memory_map_array_t *memory_maps);

memory_map_array_t *refresh_memory_maps(pid_t pid,
    memory_map_array_t *memory_maps);

memory_map_t *find_symbol_lib_by_address(const memory_map_array_t *maps,
    unsigned long addr);
