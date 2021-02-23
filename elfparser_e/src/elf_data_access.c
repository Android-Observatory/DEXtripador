#include "elf_parser.h"

extern Elf_Ehdr *elf_ehdr;
extern Elf_Phdr *elf_phdr;
extern Elf_Shdr *elf_shdr;
extern Elf_Sym  *elf_dynsym;
extern Elf_Sym  *elf_symtab;
extern Elf_Rel  **elf_rel;
extern Elf_Rela **elf_rela;
extern char *StringTable;
extern char *SymbolStringTable;
extern char *DynSymbolStringTable;

extern uint64_t dynsym_num;
extern uint64_t symtab_num;
extern size_t  rel_sections;
extern size_t  rela_sections;
/***
 * Elf header
 * Interesting functions for python
 * binding.
 */
int 
is_magic_elf()
{
    if (elf_ehdr == NULL)
    {
        return (-1);
    }

    if (elf_ehdr->e_ident[EI_MAG0] != ELFMAG0 || 
        elf_ehdr->e_ident[EI_MAG1] != ELFMAG1 || 
        elf_ehdr->e_ident[EI_MAG2] != ELFMAG2 || 
        elf_ehdr->e_ident[EI_MAG3] != ELFMAG3)
    {
        return (0);
    }

    return (1);
}

unsigned char
e_ident(size_t nident)
{
    if (elf_ehdr == NULL || nident >= EI_NIDENT)
    {
        return (unsigned char)(-1);
    }
    
    return (elf_ehdr->e_ident[nident]);
}

Elf64_Addr
e_type()
{
    if (elf_ehdr == NULL)
    {
        return (Elf64_Addr)(-1);
    }

    return (elf_ehdr->e_type);
}

Elf64_Half
e_machine()
{
    if (elf_ehdr == NULL)
    {
        return (Elf64_Half)(-1);
    }

    return (elf_ehdr->e_machine);
}

Elf64_Word
e_version()
{
    if (elf_ehdr == NULL)
    {
        return (Elf64_Word)(-1);
    }

    return (elf_ehdr->e_version);
}

Elf64_Addr
e_entry()
{
    if (elf_ehdr == NULL)
    {
        return (Elf64_Addr)(-1);
    }

    return (elf_ehdr->e_entry);
}

Elf64_Off
e_phoff()
{
    if (elf_ehdr == NULL)
    {
        return (Elf64_Off)(-1);
    }

    return (elf_ehdr->e_phoff);
}

Elf64_Off
e_shoff()
{
    if (elf_ehdr == NULL)
    {
        return (Elf64_Off)(-1);
    }

    return (elf_ehdr->e_shoff);
}

Elf64_Word
e_flags()
{
    if (elf_ehdr == NULL)
    {
        return (Elf64_Word)(-1);
    }

    return (elf_ehdr->e_flags);
}

Elf64_Half
e_ehsize()
{
    if (elf_ehdr == NULL)
    {
        return (Elf64_Half)(-1);
    }

    return (elf_ehdr->e_ehsize);
}

Elf64_Half
e_phentsize()
{
    if (elf_ehdr == NULL)
    {
        return (Elf64_Half)(-1);
    }

    return (elf_ehdr->e_phentsize);   
}

Elf64_Half
e_phnum()
{
    if (elf_ehdr == NULL)
    {
        return (Elf64_Half)(-1);
    }

    return (elf_ehdr->e_phnum);   
}

Elf64_Half
e_shentsize()
{
    if (elf_ehdr == NULL)
    {
        return (Elf64_Half)(-1);
    }

    return (elf_ehdr->e_shentsize);   
}

Elf64_Half
e_shnum()
{
    if (elf_ehdr == NULL)
    {
        return (Elf64_Half)(-1);
    }

    return (elf_ehdr->e_shnum);   
}

Elf64_Half
e_shstrndx()
{
    if (elf_ehdr == NULL)
    {
        return (Elf64_Half)(-1);
    }

    return (elf_ehdr->e_shstrndx);   
}


/***
 * Elf program header
 * Interesting functions for python
 * binding.
 */
uint32_t
p_type(size_t header)
{
    if (elf_ehdr == NULL ||
        elf_phdr == NULL ||
        header >= elf_ehdr->e_phnum)
    {
        return (uint32_t)(-1);
    }

    return (elf_phdr[header].p_type);
}

uint32_t
p_flags(size_t header)
{
    if (elf_ehdr == NULL ||
        elf_phdr == NULL ||
        header >= elf_ehdr->e_phnum)
    {
        return (uint32_t)(-1);
    }

    return (elf_phdr[header].p_flags);
}

Elf64_Off
p_offset(size_t header)
{
    if (elf_ehdr == NULL ||
        elf_phdr == NULL ||
        header >= elf_ehdr->e_phnum)
    {
        return (Elf64_Off)(-1);
    }

    return (elf_phdr[header].p_offset);
}

Elf64_Addr
p_vaddr(size_t header)
{
    if (elf_ehdr == NULL ||
        elf_phdr == NULL ||
        header >= elf_ehdr->e_phnum)
    {
        return (Elf64_Addr)(-1);
    }

    return (elf_phdr[header].p_vaddr);
}

Elf64_Addr
p_paddr(size_t header)
{
    if (elf_ehdr == NULL ||
        elf_phdr == NULL ||
        header >= elf_ehdr->e_phnum)
    {
        return (Elf64_Addr)(-1);
    }

    return (elf_phdr[header].p_paddr);
}

uint64_t 
p_filesz(size_t header)
{
    if (elf_ehdr == NULL ||
        elf_phdr == NULL ||
        header >= elf_ehdr->e_phnum)
    {
        return (uint64_t)(-1);
    }

    return (elf_phdr[header].p_filesz);
}

uint64_t
p_memsz(size_t header)
{
    if (elf_ehdr == NULL ||
        elf_phdr == NULL ||
        header >= elf_ehdr->e_phnum)
    {
        return (uint64_t)(-1);
    }

    return (elf_phdr[header].p_memsz);
}

uint64_t
p_align(size_t header)
{
    if (elf_ehdr == NULL ||
        elf_phdr == NULL ||
        header >= elf_ehdr->e_phnum)
    {
        return (uint64_t)(-1);
    }

    return (elf_phdr[header].p_align);
}

/***
 * Elf section header
 * Interesting functions for python
 * binding.
 */
uint32_t
sh_name(size_t header)
{
    if (elf_ehdr == NULL ||
        elf_shdr == NULL ||
        header >= elf_ehdr->e_shnum)
    {
        return (uint32_t)(-1);
    }

    return (elf_shdr[header].sh_name);
}

const char*
sh_name_s(size_t header)
{
    if (elf_ehdr == NULL ||
        elf_shdr == NULL ||
        StringTable == NULL ||
        header >= elf_ehdr->e_shnum)
    {
        return (const char *)(NULL);
    }

    return (&StringTable[elf_shdr[header].sh_name]);
}

uint32_t
sh_type(size_t header)
{
    if (elf_ehdr == NULL ||
        elf_shdr == NULL ||
        header >= elf_ehdr->e_shnum)
    {
        return (uint32_t)(-1);
    }

    return (elf_shdr[header].sh_type);
}

uint64_t
sh_flags(size_t header)
{
    if (elf_ehdr == NULL ||
        elf_shdr == NULL ||
        header >= elf_ehdr->e_shnum)
    {
        return (uint64_t)(-1);
    }

    return (elf_shdr[header].sh_flags);
}

Elf64_Addr
sh_addr(size_t header)
{
    if (elf_ehdr == NULL ||
        elf_shdr == NULL ||
        header >= elf_ehdr->e_shnum)
    {
        return (Elf64_Addr)(-1);
    }

    return (elf_shdr[header].sh_addr);
}

Elf64_Off
sh_offset(size_t header)
{
    if (elf_ehdr == NULL ||
        elf_shdr == NULL ||
        header >= elf_ehdr->e_shnum)
    {
        return (Elf64_Off)(-1);
    }

    return (elf_shdr[header].sh_offset);
}

uint64_t
sh_size(size_t header)
{
    if (elf_ehdr == NULL ||
        elf_shdr == NULL ||
        header >= elf_ehdr->e_shnum)
    {
        return (uint64_t)(-1);
    }

    return (elf_shdr[header].sh_size);
}

uint32_t
sh_link(size_t header)
{
    if (elf_ehdr == NULL ||
        elf_shdr == NULL ||
        header >= elf_ehdr->e_shnum)
    {
        return (uint32_t)(-1);
    }

    return (elf_shdr[header].sh_link);
}

uint32_t
sh_info(size_t header)
{
    if (elf_ehdr == NULL ||
        elf_shdr == NULL ||
        header >= elf_ehdr->e_shnum)
    {
        return (uint32_t)(-1);
    }
    
    return (elf_shdr[header].sh_info);
}

uint64_t
sh_addralign(size_t header)
{
    if (elf_ehdr == NULL ||
        elf_shdr == NULL ||
        header >= elf_ehdr->e_shnum)
    {
        return (uint64_t)(-1);
    }

    return (elf_shdr[header].sh_addralign);
}

uint64_t
sh_entsize(size_t header)
{
    if (elf_ehdr == NULL ||
        elf_shdr == NULL ||
        header >= elf_ehdr->e_shnum)
    {
        return (uint64_t)(-1);
    }

    return (elf_shdr[header].sh_entsize);
}


/***
 * Elf Dynamic Symbol header
 * Interesting functions for python
 * binding
 */
size_t
dynamic_sym_length()
{
    return (dynsym_num);
}

uint32_t
dynamic_st_name(size_t header)
{
    if (elf_dynsym == NULL ||
        header >= dynsym_num)
    {
        return (uint32_t)(-1);
    }

    return (elf_dynsym[header].st_name);
}

const char*
dynamic_st_name_s(size_t header)
{
    if (elf_dynsym == NULL ||
        DynSymbolStringTable == NULL ||
        header >= dynsym_num)
    {
        return (const char*)(NULL);
    }

    return (&DynSymbolStringTable[elf_dynsym[header].st_name]);
}

unsigned char
dynamic_st_info(size_t header)
{ 
    if (elf_dynsym == NULL ||
        header >= dynsym_num)
    {
        return (unsigned char)(-1);
    }

    return (elf_dynsym[header].st_info);
}

unsigned char
dynamic_st_other(size_t header)
{
    if (elf_dynsym == NULL ||
        header >= dynsym_num)
    {
        return (unsigned char)(-1);
    }

    return (elf_dynsym[header].st_other);
}

uint16_t
dynamic_st_shndx(size_t header)
{
    if (elf_dynsym == NULL ||
        header >= dynsym_num)
    {
        return (uint16_t)(-1);
    }

    return (elf_dynsym[header].st_shndx);
}

Elf64_Addr
dynamic_st_value(size_t header)
{  
    if (elf_dynsym == NULL ||
        header >= dynsym_num)
    {
        return (Elf64_Addr)(-1);
    }

    return (elf_dynsym[header].st_value);
}

uint64_t
dynamic_st_size(size_t header)
{
    if (elf_dynsym == NULL ||
        header >= dynsym_num)
    {
        return (uint64_t)(-1);
    }

    return (elf_dynsym[header].st_size);
}


/***
 * Elf Symtab Symbol header
 * Interesting functions for python
 * binding
 */

size_t
symtab_sym_length()
{
    return (symtab_num);
}

uint32_t
symtab_st_name(size_t header)
{
    if (elf_symtab == NULL ||
        header >= symtab_num)
    {
        return (uint32_t)(-1);
    }

    return (elf_symtab[header].st_name);
}

const char*
symtab_st_name_s(size_t header)
{
    if (elf_symtab == NULL ||
        SymbolStringTable == NULL ||
        header >= symtab_num)
    {
        return (const char*)(NULL);
    }

    return (&SymbolStringTable[elf_symtab[header].st_name]);
}

unsigned char
symtab_st_info(size_t header)
{ 
    if (elf_symtab == NULL ||
        header >= symtab_num)
    {
        return (unsigned char)(-1);
    }

    return (elf_symtab[header].st_info);
}

unsigned char
symtab_st_other(size_t header)
{
    if (elf_symtab == NULL ||
        header >= symtab_num)
    {
        return (unsigned char)(-1);
    }

    return (elf_symtab[header].st_other);
}

uint16_t
symtab_st_shndx(size_t header)
{
    if (elf_symtab == NULL ||
        header >= symtab_num)
    {
        return (uint16_t)(-1);
    }

    return (elf_symtab[header].st_shndx);
}

Elf64_Addr
symtab_st_value(size_t header)
{  
    if (elf_symtab == NULL ||
        header >= symtab_num)
    {
        return (Elf64_Addr)(-1);
    }

    return (elf_symtab[header].st_value);
}

uint64_t
symtab_st_size(size_t header)
{
    if (elf_symtab == NULL ||
        header >= symtab_num)
    {
        return (uint64_t)(-1);
    }

    return (elf_symtab[header].st_size);
}


Elf64_Addr 
rel_r_offset(size_t header, size_t index)
{
    size_t i;
    Elf_Shdr* rel_section = NULL;
    size_t  section_relocs_i;
    size_t  header_aux = header;

    if (elf_rel == NULL ||
        elf_shdr == NULL ||
        header >= rel_sections)
    {
        return (Elf64_Addr)(-1);
    }

    for ( i = 0; i < elf_ehdr->e_shnum; i++ )
    {
        if (elf_shdr[i].sh_type == SHT_REL)
        {
            if (header_aux == 0)
            {
                rel_section = &elf_shdr[i];
                break;
            }

            header_aux -= 1;
        }
    }

    if (is_32_bit_binary())
    {
        section_relocs_i = rel_section->sh_size / sizeof(Elf32_Rel);
    }
    else if (is_64_bit_binary())
    {
        section_relocs_i = rel_section->sh_size / sizeof(Elf64_Rel);
    }

    if (rel_section == NULL ||
        index >= section_relocs_i)
    {
        return (Elf64_Addr)(-1);
    }

    return (elf_rel[header][index].r_offset);
}


uint64_t
rel_r_info(size_t header, size_t index)
{
    size_t i;
    Elf_Shdr* rel_section = NULL;
    size_t  section_relocs_i;
    size_t  header_aux = header;
    
    if (elf_rel == NULL ||
        elf_shdr == NULL ||
        header >= rel_sections)
    {
        return (uint64_t)(-1);
    }

    for ( i = 0; i < elf_ehdr->e_shnum; i++ )
    {
        if (elf_shdr[i].sh_type == SHT_REL)
        {
            if (header_aux == 0)
            {
                rel_section = &elf_shdr[i];
                break;
            }

            header_aux -= 1;
        }
    }

    if (is_32_bit_binary())
    {
        section_relocs_i = rel_section->sh_size / sizeof(Elf32_Rel);
    }
    else if (is_64_bit_binary())
    {
        section_relocs_i = rel_section->sh_size / sizeof(Elf64_Rel);
    }

    if (rel_section == NULL ||
        index >= section_relocs_i)
    {
        return (uint64_t)(-1);
    }

    return (elf_rel[header][index].r_info);
}


size_t
rel_32_size()
{
    return sizeof(Elf32_Rel);
}

size_t
rel_64_size()
{
    return sizeof(Elf64_Rel);
}


Elf64_Addr rela_r_offset(size_t header, size_t index)
{
    size_t i;
    Elf_Shdr* rela_section = NULL;
    size_t  section_relocs_i;
    size_t  header_aux = header;
    
    if (elf_rela == NULL ||
        elf_shdr == NULL ||
        header >= rela_sections)
    {
        return (Elf64_Addr)(-1);
    }

    for ( i = 0; i < elf_ehdr->e_shnum; i++ )
    {
        if (elf_shdr[i].sh_type == SHT_RELA)
        {
            if (header_aux == 0)
            {
                rela_section = &elf_shdr[i];
                break;
            }

            header_aux -= 1;
        }
    }

    if (is_32_bit_binary())
    {
        section_relocs_i = rela_section->sh_size / sizeof(Elf32_Rela);
    }
    else if (is_64_bit_binary())
    {
        section_relocs_i = rela_section->sh_size / sizeof(Elf64_Rela);
    }

    if (rela_section == NULL ||
        index >= section_relocs_i)
    {
        return (Elf64_Addr)(-1);
    }

    return (elf_rela[header][index].r_offset);
}

uint64_t 
rela_r_info(size_t header, size_t index)
{
    size_t i;
    Elf_Shdr* rela_section = NULL;
    size_t  section_relocs_i;
    size_t  header_aux = header;
    
    if (elf_rela == NULL ||
        elf_shdr == NULL ||
        header >= rela_sections)
    {
        return (uint64_t)(-1);
    }

    for ( i = 0; i < elf_ehdr->e_shnum; i++ )
    {
        if (elf_shdr[i].sh_type == SHT_RELA)
        {
            if (header_aux == 0)
            {
                rela_section = &elf_shdr[i];
                break;
            }

            header_aux -= 1;
        }
    }

    if (is_32_bit_binary())
    {
        section_relocs_i = rela_section->sh_size / sizeof(Elf32_Rela);
    }
    else if (is_64_bit_binary())
    {
        section_relocs_i = rela_section->sh_size / sizeof(Elf64_Rela);
    }

    if (rela_section == NULL ||
        index >= section_relocs_i)
    {
        return (uint64_t)(-1);
    }

    return (elf_rela[header][index].r_info);
}

int64_t
rela_r_addend(size_t header, size_t index)
{
    size_t i;
    Elf_Shdr* rela_section = NULL;
    size_t  section_relocs_i;
    size_t  header_aux = header;
    
    if (elf_rela == NULL ||
        elf_shdr == NULL ||
        header >= rela_sections)
    {
        return (int64_t)(-1);
    }

    for ( i = 0; i < elf_ehdr->e_shnum; i++ )
    {
        if (elf_shdr[i].sh_type == SHT_RELA)
        {
            if (header_aux == 0)
            {
                rela_section = &elf_shdr[i];
                break;
            }

            header_aux -= 1;
        }
    }

    if (is_32_bit_binary())
    {
        section_relocs_i = rela_section->sh_size / sizeof(Elf32_Rela);
    }
    else if (is_64_bit_binary())
    {
        section_relocs_i = rela_section->sh_size / sizeof(Elf64_Rela);
    }

    if (rela_section == NULL ||
        index >= section_relocs_i)
    {
        return (int64_t)(-1);
    }

    return (elf_rela[header][index].r_addend);
}

size_t
rela_32_size()
{
    return sizeof(Elf32_Rela);
}

size_t 
rela_64_size()
{
    return sizeof(Elf64_Rela);
}