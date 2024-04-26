/*
** EPITECH PROJECT, 2024
** memory_map_utils.c
** File description:
** memory_map_utils.c.
*/
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>

#include "memory_map.h"
#include "ftrace.h"

static uint8_t test_map_information(const char *line)
{
    char filename[4096] = {};
    char perms[5];
    uint64_t start;
    uint64_t end;
    uint32_t offset;
    uint32_t major;
    uint32_t minor;
    uint32_t inode_id;

    if (sscanf(line, "%lx-%lx %4s %x %x:%x %u %[^\n]", &start,
    &end, perms, &offset, &major, &minor, &inode_id,
    filename) == 8 && inode_id != 0) {
        return 0;
    }
    return 1;
}

static uint8_t get_map_information(const char *line, memory_map_t *memory_map)
{
    char filename[4096] = {};
    char perms[5];
    uint32_t major;
    uint32_t minor;
    uint64_t filename_len;

    if (sscanf(line, "%lx-%lx %4s %x %x:%x %u %[^\n]", &memory_map->start,
    &memory_map->end, perms, &memory_map->offset, &major, &minor,
    &memory_map->inode_id, filename) == 8 && memory_map->inode_id != 0) {
        filename_len = strlen(filename);
        memory_map->filename = malloc(sizeof(char) * (filename_len + 1));
        memcpy(memory_map->filename, filename, filename_len);
        memory_map->filename[filename_len] = '\0';
        return 0;
    }
    return 1;
}

static uint64_t count_lines(FILE *fp)
{
    char line[4170];
    uint64_t count = 0;

    while (fgets(line, sizeof(line), fp))
        if (0 == test_map_information(line))
            count++;
    rewind(fp);
    return count;
}

static FILE *open_maps_file(pid_t pid)
{
    FILE *fp;
    char path[200] = {};

    snprintf(path, 200, "/proc/%i/maps", pid);
    fp = fopen(path, "r");
    return fp;
}

static uint8_t allocate_memory_map(FILE *fp, memory_map_array_t *maps)
{
    uint64_t total_lines = count_lines(fp);

    if (NULL == maps)
        return 1;
    if (0 == total_lines)
        return 1;
    maps->len = total_lines;
    maps->memory_maps = malloc(sizeof(memory_map_t) * total_lines);
    if (NULL == maps->memory_maps)
        return 1;
    return 0;
}

static void load_elf(memory_map_t *memory_map)
{
    if (1 == load_elf_file(memory_map))
        memset(&memory_map->elf_file, 0, sizeof(elf_file_t));
}

memory_map_array_t *get_memory_maps(pid_t pid)
{
    FILE *fp = open_maps_file(pid);
    char line[4170];
    memory_map_t temp_map = {};
    memory_map_array_t *maps = malloc(sizeof(memory_map_array_t));
    uint64_t count = 0;

    if (NULL == fp)
        return NULL;
    if (1 == allocate_memory_map(fp, maps))
        return NULL;
    while (fgets(line, sizeof(line), fp)) {
        if (0 == get_map_information(line, &temp_map)) {
            memcpy(&maps->memory_maps[count], &temp_map, sizeof(memory_map_t));
            load_elf(&maps->memory_maps[count]);
            count++;
        }
        memset(&temp_map, 0, sizeof(memory_map_t));
    }
    fclose(fp);
    return maps;
}

void destroy_memory_maps(memory_map_array_t *memory_maps)
{
    for (uint64_t i = 0; i < memory_maps->len; i++) {
        if (NULL != memory_maps->memory_maps[i].filename)
            free(memory_maps->memory_maps[i].filename);
        if (memory_maps->memory_maps[i].elf_file.elf != NULL)
            elf_end(memory_maps->memory_maps[i].elf_file.elf);
        if (memory_maps->memory_maps[i].elf_file.sym_shdr != NULL)
            free(memory_maps->memory_maps[i].elf_file.sym_shdr);
        if (memory_maps->memory_maps[i].elf_file.dyn_shdr != NULL)
            free(memory_maps->memory_maps[i].elf_file.dyn_shdr);
        if (memory_maps->memory_maps[i].elf_file.plt_shdr != NULL)
            free(memory_maps->memory_maps[i].elf_file.plt_shdr);
    }
    free(memory_maps->memory_maps);
    free(memory_maps);
}
