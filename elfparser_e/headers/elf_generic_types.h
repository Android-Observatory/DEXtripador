#include <elf.h>

#ifndef ELF_GENERIC_TYPES_H
#define ELF_GENERIC_TYPES_H

typedef struct elf_ehdr
{
  unsigned char e_ident[EI_NIDENT]; /* ELF "magic number" */
  Elf64_Half e_type;
  Elf64_Half e_machine;
  Elf64_Word e_version;
  Elf64_Addr e_entry; /* Entry point virtual address */
  Elf64_Off e_phoff;  /* Program header table file offset */
  Elf64_Off e_shoff;  /* Section header table file offset */
  Elf64_Word e_flags;
  Elf64_Half e_ehsize;
  Elf64_Half e_phentsize;
  Elf64_Half e_phnum;
  Elf64_Half e_shentsize;
  Elf64_Half e_shnum;
  Elf64_Half e_shstrndx;
} Elf_Ehdr;

typedef struct elf_phdr
{
  uint32_t p_type;
  uint32_t p_flags;
  Elf64_Off p_offset;
  Elf64_Addr p_vaddr;
  Elf64_Addr p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
} Elf_Phdr;

typedef struct elf_shdr
{
  uint32_t sh_name;
  uint32_t sh_type;
  uint64_t sh_flags;
  Elf64_Addr sh_addr;
  Elf64_Off sh_offset;
  uint64_t sh_size;
  uint32_t sh_link;
  uint32_t sh_info;
  uint64_t sh_addralign;
  uint64_t sh_entsize;
} Elf_Shdr;

typedef struct elf_sym
{
  uint32_t st_name;
  unsigned char st_info;
  unsigned char st_other;
  uint16_t st_shndx;
  Elf64_Addr st_value;
  uint64_t st_size;
} Elf_Sym;

typedef struct elf_rel
{
  Elf64_Addr  r_offset;
  uint64_t    r_info;
} Elf_Rel;

typedef struct elf_rela
{
  Elf64_Addr  r_offset;
  uint64_t    r_info;
  int64_t     r_addend;
} Elf_Rela;

#endif