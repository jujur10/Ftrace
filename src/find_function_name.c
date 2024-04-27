/*
** EPITECH PROJECT, 2024
** find_function_name.c
** File description:
** functions to find function name
*/

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>

#include "memory_map.h"
#include "ftrace.h"


static char *find_local_symbol(const elf_file_t lib_content,
    const unsigned long call_addr)
{
    GElf_Sym sym;
    size_t nb_sym;
    char *fct_name = NULL;

    if (lib_content.sym_shdr == NULL || lib_content.sym_data == NULL)
        return NULL;
    nb_sym = lib_content.sym_shdr->sh_size / lib_content.sym_shdr->sh_entsize;
    for (size_t i = 0; i < nb_sym; ++i) {
        if (gelf_getsym(lib_content.sym_data, i, &sym) == NULL)
            return NULL;
        if (sym.st_value == call_addr)
            fct_name = elf_strptr(lib_content.elf,
                lib_content.sym_shdr->sh_link, sym.st_name);
        if (sym.st_value == call_addr && strlen(fct_name) != 0)
            return fct_name;
    }
    return NULL;
}

static char *find_dynamic_symbol(const elf_file_t lib_content,
    const unsigned long lib_offset)
{
    GElf_Rela rela;
    GElf_Sym sym;
    size_t nb_sym;

    if (lib_content.plt_data == NULL || lib_content.plt_shdr == NULL ||
    lib_content.dyn_data == NULL || lib_content.dyn_shdr == NULL)
        return NULL;
    nb_sym = lib_content.plt_shdr->sh_size / lib_content.plt_shdr->sh_entsize;
    for (size_t i = 0; i < nb_sym; i++) {
        if (gelf_getrela(lib_content.plt_data, i, &rela) == NULL)
            return NULL;
        if (rela.r_offset != lib_offset)
            continue;
        if (gelf_getsym(lib_content.dyn_data, GELF_R_SYM(rela.r_info), &sym)
        == NULL)
            return NULL;
        return elf_strptr(lib_content.elf, lib_content.dyn_shdr->sh_link,
            sym.st_name);
    }
    return NULL;
}

static long compute_dynamic_lib_offset(const pid_t pid,
    const unsigned long call_addr)
{
    const long full_addr = ptrace(PTRACE_PEEKTEXT, pid, call_addr + 2);
    const long jump_offset = full_addr & 0xFFFFFFFF;

    if (full_addr == -1)
        return -1;
    return call_addr + 6 + jump_offset;
}

static char *find_function_name(const memory_map_t *lib,
    const pid_t pid,
    const unsigned long call_address)
{
    char *f_name = NULL;
    const long dynamic_offset = compute_dynamic_lib_offset(pid, call_address);
    const elf_file_t lib_content = lib->elf_file;

    if (dynamic_offset == -1)
        return NULL;
    f_name = find_dynamic_symbol(lib_content, dynamic_offset);
    if (f_name)
        return f_name;
    f_name = find_local_symbol(lib_content,
        call_address - (lib->is_pie ? lib->start : 0));
    if (f_name)
        return f_name;
    return NULL;
}

static memory_map_t *case_where_lib_null(memory_map_array_t **maps,
    const pid_t pid, const unsigned long call_address)
{
    *maps = refresh_memory_maps(pid, *maps);
    return find_symbol_lib_by_address(*maps, call_address);
}

void create_function_name(memory_map_array_t **maps,
    const pid_t pid,
    const unsigned long call_address,
    const char *tracee_bin_name)
{
    memory_map_t *lib = find_symbol_lib_by_address(*maps, call_address);
    char print[256] = {0};
    char *fct_name;

    lib = (lib == NULL) ? case_where_lib_null(maps, pid, call_address) : lib;
    if (lib == NULL) {
        snprintf(print, 256, "func_%#lx@%s", call_address, tracee_bin_name);
    } else {
        fct_name = find_function_name(lib, pid, call_address);
        if (fct_name == NULL)
            snprintf(print, 256, "func_%#lx@%s", call_address, lib->filename);
        else
            snprintf(print, 256, "%s", fct_name);
    }
    print_entering_function(print, strlen(print), call_address);
    strcpy(fct_stack.fct_stack[fct_stack.len], print);
    fct_stack.len++;
}
