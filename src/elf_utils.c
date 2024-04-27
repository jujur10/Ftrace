/*
** EPITECH PROJECT, 2024
** elf_utils.c
** File description:
** elf_utils.c.
*/
#include <fcntl.h>
#include <libelf.h>
#include <stddef.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>

#include "ftrace.h"
#include "memory_map.h"

uint8_t verify_elf(Elf *elf)
{
    const char *ehdr_ident = NULL;

    ehdr_ident = elf_getident(elf, NULL);
    if (NULL == ehdr_ident || !(ehdr_ident[0] == '\x7f' &&
    ehdr_ident[1] == '\x45' &&
    ehdr_ident[2] == '\x4C' &&
    ehdr_ident[3] == '\x46')) {
        return 1;
    }
    return 0;
}

char *get_symbol_from_address(Elf *elf, const section_table_t *symbol_table,
    uint64_t address)
{
    const Elf64_Shdr *shdr = symbol_table->shdr;
    const Elf64_Sym *symtab = symbol_table->symtab;
    uint64_t sym_count = symbol_table->sym_count;

    for (uint64_t i = 0; i < sym_count; ++i)
        if (address >= symtab[i].st_value && address < symtab[i].st_value +
        symtab[i].st_size)
            return elf_strptr(elf, shdr->sh_link, symtab[i].st_name);
    return NULL;
}

static uint8_t get_symbol_table(elf_file_t *elf_file)
{
    Elf_Scn *scn = NULL;
    GElf_Shdr *shdr = malloc(sizeof(GElf_Shdr));

    if (shdr == NULL)
        return 1;
    scn = elf_nextscn(elf_file->elf, scn);
    while (scn != NULL) {
        gelf_getshdr(scn, shdr);
        if (shdr->sh_type == SHT_SYMTAB)
            break;
        scn = elf_nextscn(elf_file->elf, scn);
    }
    if (scn == NULL) {
        free(shdr);
        return 0;
    }
    elf_file->sym_shdr = shdr;
    elf_file->sym_data = elf_getdata(scn, NULL);
    return 0;
}

static uint8_t get_dyn_sym(elf_file_t *elf_file)
{
    Elf_Scn *scn = NULL;
    GElf_Shdr *shdr = malloc(sizeof(GElf_Shdr));

    if (shdr == NULL)
        return 1;
    scn = elf_nextscn(elf_file->elf, scn);
    while (scn != NULL) {
        gelf_getshdr(scn, shdr);
        if (shdr->sh_type == SHT_DYNSYM) {
            break;
        }
        scn = elf_nextscn(elf_file->elf, scn);
    }
    if (scn == NULL) {
        free(shdr);
        return 0;
    }
    elf_file->dyn_shdr = shdr;
    elf_file->dyn_data = elf_getdata(scn, NULL);
    return 0;
}

static uint8_t free_and_return(GElf_Shdr *shdr, uint8_t ret_val)
{
    free(shdr);
    return ret_val;
}

static uint8_t get_rela_plt(elf_file_t *elf_file)
{
    Elf_Scn *scn = NULL;
    GElf_Shdr *shdr = malloc(sizeof(GElf_Shdr));
    size_t ndxptr = 0;

    if (shdr == NULL)
        return 1;
    if (-1 == elf_getshdrstrndx(elf_file->elf, &ndxptr))
        return free_and_return(shdr, 1);
    scn = elf_nextscn(elf_file->elf, scn);
    while (scn != NULL) {
        gelf_getshdr(scn, shdr);
        if (shdr->sh_type == SHT_RELA && strcmp(".rela.plt",
            elf_strptr(elf_file->elf, ndxptr, shdr->sh_name)) == 0)
            break;
        scn = elf_nextscn(elf_file->elf, scn);
    }
    if (scn == NULL)
        return free_and_return(shdr, 0);
    elf_file->plt_shdr = shdr;
    elf_file->plt_data = elf_getdata(scn, NULL) SEMICOLON return 0;
}

static void ckeck_is_pie(memory_map_t *memory_map)
{
    GElf_Ehdr elf_header;

    gelf_getehdr(memory_map->elf_file.elf, &elf_header);
    memory_map->is_pie = (ET_DYN == elf_header.e_type) ? 1 : 0;
}

uint8_t load_elf_file(memory_map_t *memory_map)
{
    int fd;

    if (0 != memory_map->offset)
        return 1;
    fd = open(memory_map->filename, O_RDONLY);
    if (-1 == fd)
        return 1;
    memory_map->elf_file.fd = fd;
    memory_map->elf_file.elf = elf_begin(fd, ELF_C_READ, NULL);
    if (NULL == memory_map->elf_file.elf)
        return (uint8_t)close(fd) * 0 + 1;
    if (get_symbol_table(&memory_map->elf_file) == 1
    || get_rela_plt(&memory_map->elf_file) == 1
    || get_dyn_sym(&memory_map->elf_file) == 1) {
        elf_end(memory_map->elf_file.elf);
        return (uint8_t)close(fd) * 0 + 1;
    }
    ckeck_is_pie(memory_map);
    return 0;
}
