#include "elf_generic_types.h"
#include <stdio.h>
#include <string.h>
#include "memory_management.h"
#include "file_management.h"

#ifndef ELF_PARSER_H
#define ELF_PARSER_H


// Some lost defines

// .note.gnu.property notes sections.
#ifndef PT_GNU_PROPERTY
#define PT_GNU_PROPERTY 0x6474e553
#endif

// Fill with random data.
#ifndef PT_OPENBSD_RANDOMIZE
#define PT_OPENBSD_RANDOMIZE 0x65a3dbe6
#endif

// Program does W^X violations.
#ifndef PT_OPENBSD_WXNEEDED
#define PT_OPENBSD_WXNEEDED 0x65a3dbe7
#endif

// Section for boot arguments.
#ifndef PT_OPENBSD_BOOTDATA
#define PT_OPENBSD_BOOTDATA 0x65a41be6
#endif

// ARM program header types.
// Platform architecture compatibility info
#ifndef PT_ARM_ARCHEXT
#define PT_ARM_ARCHEXT 0x70000000
#endif


int parse_elf(const char *pathname);

/***
 * Elf header parsing, useful functions
 * and printing
 */
int parse_elf_ehdr(uint8_t *buf_ptr, size_t file_size);
int is_32_bit_binary();
int is_64_bit_binary();
const Elf_Ehdr *get_elf_ehdr_read();
void print_elf_ehdr();

/***
 * Elf header
 * Interesting functions for python
 * binding.
 */
int is_magic_elf();
unsigned char e_ident(size_t nident);
Elf64_Addr e_type();
Elf64_Half e_machine();
Elf64_Word e_version();
Elf64_Addr e_entry();
Elf64_Off e_phoff();
Elf64_Off e_shoff();
Elf64_Word e_flags();
Elf64_Half e_ehsize();
Elf64_Half e_phentsize();
Elf64_Half e_phnum();
Elf64_Half e_shentsize();
Elf64_Half e_shnum();
Elf64_Half e_shstrndx();

/***
 * Program header parsing and printing
 */
int parse_elf_phdr(uint8_t *buf_ptr, size_t file_size);
void print_elf_phdr();

/***
 * Elf program header
 * Interesting functions for python
 * binding.
 */
uint32_t p_type(size_t header);
uint32_t p_flags(size_t header);
Elf64_Off p_offset(size_t header);
Elf64_Addr p_vaddr(size_t header);
Elf64_Addr p_paddr(size_t header);
uint64_t p_filesz(size_t header);
uint64_t p_memsz(size_t header);
uint64_t p_align(size_t header);

/***
 * Section header parsing and printing
 */
int parse_elf_shdr(uint8_t *buf_ptr, size_t file_size);
void print_elf_shdr();

/***
 * Elf section header
 * Interesting functions for python
 * binding.
 */
uint32_t sh_name(size_t header);
const char* sh_name_s(size_t header);
uint32_t sh_type(size_t header);
uint64_t sh_flags(size_t header);
Elf64_Addr sh_addr(size_t header);
Elf64_Off sh_offset(size_t header);
uint64_t sh_size(size_t header);
uint32_t sh_link(size_t header);
uint32_t sh_info(size_t header);
uint64_t sh_addralign(size_t header);
uint64_t sh_entsize(size_t header);

/***
 * Symbols header parsing and printing
 */
int parse_elf_sym(uint8_t *buf_ptr);
void print_elf_sym();

/***
 * Elf Dynamic Symbol header
 * Interesting functions for python
 * binding
 */
size_t dynamic_sym_length();
uint32_t dynamic_st_name(size_t header);
const char* dynamic_st_name_s(size_t header);
unsigned char dynamic_st_info(size_t header);
unsigned char dynamic_st_other(size_t header);
uint16_t dynamic_st_shndx(size_t header);
Elf64_Addr dynamic_st_value(size_t header);
uint64_t dynamic_st_size(size_t header);

/***
 * Elf Symtab Symbol header
 * Interesting functions for python
 * binding
 */
size_t symtab_sym_length();
uint32_t symtab_st_name(size_t header);
const char* symtab_st_name_s(size_t header);
unsigned char symtab_st_info(size_t header);
unsigned char symtab_st_other(size_t header);
uint16_t symtab_st_shndx(size_t header);
Elf64_Addr symtab_st_value(size_t header);
uint64_t symtab_st_size(size_t header);

/***
 * Relocation header parsing and printing
 */
int parse_elf_rel_a(uint8_t *buf_ptr, size_t file_size);
void print_elf_rel_a();

/***
 * Elf Rel header
 * Interesting functions for python
 * binding
 */
Elf64_Addr  rel_r_offset(size_t header, size_t index);
uint64_t    rel_r_info(size_t header, size_t index);

size_t      rel_32_size();
size_t      rel_64_size();

/***
 * Elf Rela header
 * Interesting functions for python
 * binding
 */
Elf64_Addr  rela_r_offset(size_t header, size_t index);
uint64_t    rela_r_info(size_t header, size_t index);
int64_t     rela_r_addend(size_t header, size_t index);

size_t      rela_32_size();
size_t      rela_64_size();

/***
 * DYNAMIC Program header parsing and printing
 */
int parse_elf_dynamic(uint8_t *buf_ptr, size_t file_size);
void print_elf_dynamic();

/***
 * Printer functions, good for analsts
 */
void print_imported_libraries();
void print_imported_functions();

void print_exported_libraries();
void print_exported_functions();


void close_everything();

#endif