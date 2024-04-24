/*
** EPITECH PROJECT, 2024
** elf_utils.c
** File description:
** elf_utils.c.
*/
#include <libelf.h>
#include <stddef.h>
#include <stdio.h>

#include "ftrace.h"

uint8_t verify_elf(Elf *elf)
{
    const char *ehdr_ident = NULL;

    ehdr_ident = elf_getident(elf, NULL);
    if (!(ehdr_ident[0] == '\x7f' &&
          ehdr_ident[1] == '\x45' &&
          ehdr_ident[2] == '\x4C' &&
          ehdr_ident[3] == '\x46')) {
        return 1;
    }
    return 0;
}

uint8_t get_symbol_table(Elf *elf, symbol_table_t *symbol_table)
{
    Elf_Scn *scn = NULL;
    Elf64_Shdr *shdr = NULL;
    Elf_Data *section;
    int count = 0;

    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        shdr = elf64_getshdr(scn);
        if (SHT_SYMTAB == shdr->sh_type || shdr->sh_type == SHT_DYNSYM) {
            if (count == 1) {
                section = elf_getdata(scn, NULL);
                symbol_table->symtab = section->d_buf;
                symbol_table->sym_count = shdr->sh_size / shdr->sh_entsize;
                symbol_table->shdr = shdr;
                return 0;
            }
            count++;
        }
    }
    return 1;
}

//Trouver un moyen pour explorer toutes les tables (il y en a 2)
//pour voir ou se trouve l'adresse

char *get_symbol_from_address(Elf *elf, const symbol_table_t *symbol_table,
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
