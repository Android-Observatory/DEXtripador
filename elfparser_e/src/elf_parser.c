#include "elf_parser.h"

Elf_Ehdr *elf_ehdr = NULL;
Elf_Phdr *elf_phdr = NULL;
Elf_Shdr *elf_shdr = NULL;
Elf_Sym *elf_dynsym = NULL;
Elf_Sym *elf_symtab = NULL;
Elf_Rel **elf_rel = NULL;
Elf_Rela **elf_rela = NULL;
Elf_Dyn *elf_dyn = NULL;

uint8_t *buf_ptr = NULL;
size_t buf_ptr_size = 0;
char *Interpreter = NULL;
char *StringTable = NULL;
char *SymbolStringTable = NULL;
char *DynSymbolStringTable = NULL;
uint64_t dynsym_num = 0, symtab_num = 0;
size_t rel_sections, rela_sections;
size_t dynamic_headers = 0;

int parse_elf(const char *pathname)
{
    int fd;

    ssize_t file_size;

    if ((fd = open_file_reading(pathname)) < 0)
        return (-1);

    if ((file_size = get_file_size(fd)) < 0)
        return (-1);

    buf_ptr_size = file_size;

    if ((buf_ptr = mmap_file_read((size_t)file_size, fd)) == NULL)
    {
        close_file(fd);
        return (-1);
    }

    if (parse_elf_ehdr(buf_ptr, (size_t)file_size) < 0)
    {
        close_file(fd);
        munmap_memory(buf_ptr, (size_t)file_size);
        return (-1);
    }

    if (parse_elf_phdr(buf_ptr, (size_t)file_size) < 0)
    {
        close_file(fd);
        munmap_memory(buf_ptr, (size_t)file_size);
        return (-1);
    }

    if (parse_elf_shdr(buf_ptr, (size_t)file_size) < 0)
    {
        close_file(fd);
        munmap_memory(buf_ptr, (size_t)file_size);
        return (-1);
    }

    if (parse_elf_sym(buf_ptr) < 0)
    {
        close_file(fd);
        munmap_memory(buf_ptr, (size_t)file_size);
        return (-1);
    }

    if (parse_elf_rel_a(buf_ptr, (size_t)file_size) < 0)
    {
        close_file(fd);
        munmap_memory(buf_ptr, (size_t)file_size);
        return (-1);
    }

    if (parse_elf_dynamic(buf_ptr, (size_t)file_size) < 0)
    {
        close_file(fd);
        munmap_memory(buf_ptr, (size_t)file_size);
        return (-1);
    }

    close_file(fd);

    return (0);
}

/***
 * Elf header parsing, useful functions
 * and printing
 */
int parse_elf_ehdr(uint8_t *buf_ptr, size_t file_size)
{
    Elf32_Ehdr *elf32_ehdr;
    Elf64_Ehdr *elf64_ehdr;
    char *e_ident;

    if (buf_ptr == NULL)
    {
        fprintf(stderr, "parse_elf_hdr: cannot parse null buffer\n");
        return (-1);
    }

    if (file_size < EI_NIDENT)
    {
        fprintf(stderr, "parse_elf_hdr: file size incorrect for parsing, invalid elf file\n");
        return (-1);
    }
    // point to buffer and do checks
    e_ident = (char *)buf_ptr;

    if (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 || e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3)
    {
        fprintf(stderr, "parse_elf_hdr: elf incorrect header\n");
        return (-1);
    }

    if (elf_ehdr != NULL)
    {
        free_memory(elf_ehdr);
        elf_ehdr = NULL;
    }

    elf_ehdr = allocate_memory(sizeof(Elf_Ehdr));

    if (e_ident[EI_CLASS] == ELFCLASS32) // if 32 bit binary
    {

        if (file_size < sizeof(Elf32_Ehdr))
        {
            fprintf(stderr, "parse_elf_ehdr: file size incorrect for parsing, invalid elf file\n");
            return (-1);
        }

        elf32_ehdr = (Elf32_Ehdr *)buf_ptr;

        memcpy(elf_ehdr->e_ident, elf32_ehdr->e_ident, EI_NIDENT);
        elf_ehdr->e_type = elf32_ehdr->e_type;
        elf_ehdr->e_machine = elf32_ehdr->e_machine;
        elf_ehdr->e_version = elf32_ehdr->e_version;
        elf_ehdr->e_entry = elf32_ehdr->e_entry;
        elf_ehdr->e_phoff = elf32_ehdr->e_phoff;
        elf_ehdr->e_shoff = elf32_ehdr->e_shoff;
        elf_ehdr->e_flags = elf32_ehdr->e_flags;
        elf_ehdr->e_ehsize = elf32_ehdr->e_ehsize;
        elf_ehdr->e_phentsize = elf32_ehdr->e_phentsize;
        elf_ehdr->e_phnum = elf32_ehdr->e_phnum;
        elf_ehdr->e_shentsize = elf32_ehdr->e_shentsize;
        elf_ehdr->e_shnum = elf32_ehdr->e_shnum;
        elf_ehdr->e_shstrndx = elf32_ehdr->e_shstrndx;
    }
    else if (e_ident[EI_CLASS] == ELFCLASS64) // if 64 bit binary
    {
        if (file_size < sizeof(Elf64_Ehdr))
        {
            fprintf(stderr, "parse_elf_ehdr: file size incorrect for parsing, invalid elf file\n");
            return (-1);
        }

        elf64_ehdr = (Elf64_Ehdr *)buf_ptr;

        memcpy(elf_ehdr->e_ident, elf64_ehdr->e_ident, EI_NIDENT);
        elf_ehdr->e_type = elf64_ehdr->e_type;
        elf_ehdr->e_machine = elf64_ehdr->e_machine;
        elf_ehdr->e_version = elf64_ehdr->e_version;
        elf_ehdr->e_entry = elf64_ehdr->e_entry;
        elf_ehdr->e_phoff = elf64_ehdr->e_phoff;
        elf_ehdr->e_shoff = elf64_ehdr->e_shoff;
        elf_ehdr->e_flags = elf64_ehdr->e_flags;
        elf_ehdr->e_ehsize = elf64_ehdr->e_ehsize;
        elf_ehdr->e_phentsize = elf64_ehdr->e_phentsize;
        elf_ehdr->e_phnum = elf64_ehdr->e_phnum;
        elf_ehdr->e_shentsize = elf64_ehdr->e_shentsize;
        elf_ehdr->e_shnum = elf64_ehdr->e_shnum;
        elf_ehdr->e_shstrndx = elf64_ehdr->e_shstrndx;
    }
    else
    {
        fprintf(stderr, "parse_elf_ehdr: elf type (%d) not supported\n", (int)e_ident[4]);
        return (-1);
    }

    if (elf_ehdr->e_ehsize > file_size)
    {
        fprintf(stderr, "parse_elf_ehdr: elf header out of file bound\n");
        return (-1);
    }

    if (elf_ehdr->e_phoff > file_size || (elf_ehdr->e_phoff + (elf_ehdr->e_phentsize * elf_ehdr->e_phnum)) > file_size)
    {
        fprintf(stderr, "parse_elf_ehdr: program header out of file bound\n");
        return (-1);
    }

    if (elf_ehdr->e_shoff > file_size || (elf_ehdr->e_shoff + (elf_ehdr->e_shentsize * elf_ehdr->e_shnum)) > file_size)
    {
        fprintf(stderr, "parse_elf_ehdr: section header out of file bound\n");
        return (-1);
    }

    return (0);
}

int is_32_bit_binary()
{
    if (elf_ehdr == NULL)
        return (-1);

    if (elf_ehdr->e_ident[EI_CLASS] == ELFCLASS32)
        return (1);
    else
        return (0);
}

int is_64_bit_binary()
{
    if (elf_ehdr == NULL)
        return (-1);

    if (elf_ehdr->e_ident[EI_CLASS] == ELFCLASS64)
        return (1);
    else
        return (0);
}

const Elf_Ehdr *
get_elf_ehdr_read()
{
    return elf_ehdr;
}

/*
 * Auxiliar methods to print names instead of simple
 * numbers from the ElfN_Ehdr header
 */
static void
print_elf_class(unsigned char e_ident)
{
    char *class;

    if (e_ident == ELFCLASSNONE)
        class = "ELFCLASSNONE";
    else if (e_ident == ELFCLASS32)
        class = "ELFCLASS32";
    else if (e_ident == ELFCLASS64)
        class = "ELFCLASS64";
    else
    {
        printf("ELF_CLASS:                              %x\n", e_ident);
        return;
    }

    printf("ELF_CLASS:                              %s\n", class);
}

static void
print_elf_data(unsigned char e_data)
{
    char *data;

    if (e_data == ELFDATANONE)
        data = "ELFDATANONE";
    else if (e_data == ELFDATA2LSB)
        data = "ELFDATA2LSB (Two's complement, little-endian)";
    else if (e_data == ELFDATA2MSB)
        data = "ELFDATA2MSB (Two's complement, big-endian)";
    else
    {
        printf("ELF_DATA:                               %x (No fucking idea)\n", e_data);
        return;
    }

    printf("ELF_DATA:                               %s\n", data);
}

static void
print_elf_version(unsigned char e_version)
{
    char *version;

    if (e_version == EV_NONE)
        version = "EV_NONE";
    else if (e_version == EV_CURRENT)
        version = "EV_CURRENT";
    else
    {
        printf("ELF_VERSION:                            %x\n", e_version);
        return;
    }

    printf("ELF_VERSION:                            %s\n", version);
}

static void
print_elf_osabi(unsigned char e_osabi)
{
    char *osabi;

    switch (e_osabi)
    {
    case ELFOSABI_SYSV:
        osabi = "ELFOSABI_SYSV";
        break;
    case ELFOSABI_HPUX:
        osabi = "ELFOSABI_HPUX";
        break;
    case ELFOSABI_NETBSD:
        osabi = "ELFOSABI_NETBSD";
        break;
    case ELFOSABI_LINUX:
        osabi = "ELFOSABI_LINUX";
        break;
    case ELFOSABI_SOLARIS:
        osabi = "ELFOSABI_SOLARIS";
        break;
    case ELFOSABI_AIX:
        osabi = "ELFOSABI_AIX";
        break;
    case ELFOSABI_IRIX:
        osabi = "ELFOSABI_IRIX";
        break;
    case ELFOSABI_FREEBSD:
        osabi = "ELFOSABI_FREEBSD";
        break;
    case ELFOSABI_TRU64:
        osabi = "ELFOSABI_TRU64";
        break;
    case ELFOSABI_MODESTO:
        osabi = "ELFOSABI_MODESTO";
        break;
    case ELFOSABI_OPENBSD:
        osabi = "ELFOSABI_OPENBSD";
        break;
    case ELFOSABI_ARM_AEABI:
        osabi = "ELFOSABI_ARM_AEABI";
        break;
    case ELFOSABI_ARM:
        osabi = "ELFOSABI_ARM";
        break;
    case ELFOSABI_STANDALONE:
        osabi = "ELFOSABI_STANDALONE";
        break;
    default:
        printf("ELF_OSABI:                              %x\n", e_osabi);
        return;
    }

    printf("ELF_OSABI:                              %s\n", osabi);
}

static void
print_emachine(unsigned char machine)
{
    printf("Machine:%32s", " ");
    switch (machine)
    {
    case EM_NONE:
        printf("No machine\n");
        break;
    case EM_M32:
        printf("AT&T WE 32100\n");
        break;
    case EM_SPARC:
        printf("Sun Microsystems SPARC\n");
        break;
    case EM_386:
        printf("Intel 80386\n");
        break;
    case EM_68K:
        printf("Motorola 68000 family\n");
        break;
    case EM_88K:
        printf("Motorola 88000 family\n");
        break;
    case EM_860:
        printf("Intel 80860\n");
        break;
    case EM_MIPS:
        printf("MIPS RS3000 (big-endian only)\n");
        break;
    case EM_S370:
        printf("IBM System/370\n");
        break;
    case EM_MIPS_RS3_LE:
        printf("MIPS R3000 little-endian\n");
        break;
    case EM_PARISC:
        printf("HP/PA\n");
        break;
    case EM_VPP500:
        printf("Fujitsu VPP500\n");
        break;
    case EM_SPARC32PLUS:
        printf("SPARC with enhanced instruction set (Sun's \"v8plus\")\n");
        break;
    case EM_960:
        printf("Intel 80960\n");
        break;
    case EM_PPC:
        printf("PowerPC\n");
        break;
    case EM_PPC64:
        printf("PowerPC 64-bit\n");
        break;
    case EM_S390:
        printf("IBM S/390\n");
        break;
    case EM_V800:
        printf("NEC V800 series\n");
        break;
    case EM_FR20:
        printf("Fujitsu FR20\n");
        break;
    case EM_RH32:
        printf("TRW RH-32\n");
        break;
    case EM_RCE:
        printf("Motorola RCE\n");
        break;
    case EM_ARM:
        printf("Advanced RISC Machines\n");
        break;
    case EM_FAKE_ALPHA:
        printf("Digital Alpha\n");
        break;
    case EM_SH:
        printf("Renesas SuperH (formerly Hitachi SH)\n");
        break;
    case EM_SPARCV9:
        printf("SPARC v9 64-bit\n");
        break;
    case EM_TRICORE:
        printf("Siemens Tricore\n");
        break;
    case EM_ARC:
        printf("Argonaut RISC Core\n");
        break;
    case EM_H8_300:
        printf("Hitachi H8/300\n");
        break;
    case EM_H8_300H:
        printf("Hitachi H8/300H\n");
        break;
    case EM_H8S:
        printf("Hitachi H8S\n");
        break;
    case EM_H8_500:
        printf("Hitachi H8/500\n");
        break;
    case EM_IA_64:
        printf("Intel Itanium (Merced)\n");
        break;
    case EM_MIPS_X:
        printf("Stanford MIPS-X\n");
        break;
    case EM_COLDFIRE:
        printf("Motorola Coldfire\n");
        break;
    case EM_68HC12:
        printf("Motorola M68HC12\n");
        break;
    case EM_MMA:
        printf("Fujitsu MMA Multimedia Accelerator\n");
        break;
    case EM_PCP:
        printf("Siemens PCP\n");
        break;
    case EM_NCPU:
        printf("Sony nCPU embeeded RISC\n");
        break;
    case EM_NDR1:
        printf("Denso NDR1 microprocessor\n");
        break;
    case EM_STARCORE:
        printf("Motorola Start*Core processor\n");
        break;
    case EM_ME16:
        printf("Toyota ME16 processor\n");
        break;
    case EM_ST100:
        printf("STMicroelectronic ST100 processor\n");
        break;
    case EM_TINYJ:
        printf("Advanced Logic Corp. Tinyj emb.fam\n");
        break;
    case EM_X86_64:
        printf("AMD x86-64\n");
        break;
    case EM_PDSP:
        printf("Sony DSP Processor\n");
        break;
    case EM_FX66:
        printf("Siemens FX66 microcontroller\n");
        break;
    case EM_ST9PLUS:
        printf("STMicroelectronics ST9+ 8/16 mc\n");
        break;
    case EM_ST7:
        printf("STmicroelectronics ST7 8 bit mc\n");
        break;
    case EM_68HC16:
        printf("Motorola MC68HC16 microcontroller\n");
        break;
    case EM_68HC11:
        printf("Motorola MC68HC11 microcontroller\n");
        break;
    case EM_68HC08:
        printf("Motorola MC68HC08 microcontroller\n");
        break;
    case EM_68HC05:
        printf("Motorola MC68HC05 microcontroller\n");
        break;
    case EM_SVX:
        printf("Silicon Graphics SVx\n");
        break;
    case EM_ST19:
        printf("STMicroelectronics ST19 8 bit mc\n");
        break;
    case EM_VAX:
        printf("DEC Vax\n");
        break;
    case EM_CRIS:
        printf("Axis Communications 32-bit embedded processor\n");
        break;
    case EM_JAVELIN:
        printf("Infineon Technologies 32-bit embedded processor\n");
        break;
    case EM_FIREPATH:
        printf("Element 14 64-bit DSP Processor\n");
        break;
    case EM_ZSP:
        printf("LSI Logic 16-bit DSP Processor\n");
        break;
    case EM_MMIX:
        printf("Donald Knuth's educational 64-bit processor\n");
        break;
    case EM_HUANY:
        printf("Harvard University machine-independent object files\n");
        break;
    case EM_PRISM:
        printf("SiTera Prism\n");
        break;
    case EM_AVR:
        printf("Atmel AVR 8-bit microcontroller\n");
        break;
    case EM_FR30:
        printf("Fujitsu FR30\n");
        break;
    case EM_D10V:
        printf("Mitsubishi D10V\n");
        break;
    case EM_D30V:
        printf("Mitsubishi D30V\n");
        break;
    case EM_V850:
        printf("NEC v850\n");
        break;
    case EM_M32R:
        printf("Mitsubishi M32R\n");
        break;
    case EM_MN10300:
        printf("Matsushita MN10300\n");
        break;
    case EM_MN10200:
        printf("Matsushita MN10200\n");
        break;
    case EM_PJ:
        printf("picoJava\n");
        break;
    case EM_OPENRISC:
        printf("OpenRISC 32-bit embedded processor\n");
        break;
    case EM_ARC_A5:
        printf("ARC Cores Tangent-A5\n");
        break;
    case EM_XTENSA:
        printf("Tensilica Xtensa Architecture\n");
        break;
    case EM_ALTERA_NIOS2:
        printf("Altera Nios II\n");
        break;
    case EM_AARCH64:
        printf("ARM AARCH64\n");
        break;
    case EM_TILEPRO:
        printf("Tilera TILEPro\n");
        break;
    case EM_MICROBLAZE:
        printf("Xilinx MicroBlaze\n");
        break;
    case EM_TILEGX:
        printf("Tilera TILE-Gx\n");
        break;
    default:
        printf("Make me do my job properly\n");
        //printf("An unknown machine\n");
        break;
    }
}

void print_elf_ehdr()
{
    int i;
    printf("\nElf Header\n");

    printf("Elf magic: ");
    for (i = 0; i < EI_NIDENT; i++)
    {
        if (i >= EI_MAG1 && i <= EI_MAG3)
            printf("%c ", elf_ehdr->e_ident[i]);
        else
            printf("%x ", elf_ehdr->e_ident[i]);
    }
    printf("\n");

    print_elf_class(elf_ehdr->e_ident[EI_CLASS]);
    print_elf_data(elf_ehdr->e_ident[EI_DATA]);

    print_elf_version(elf_ehdr->e_ident[EI_VERSION]);
    print_elf_osabi(elf_ehdr->e_ident[EI_OSABI]);

    printf("Elf ABI Version:                        %d\n", elf_ehdr->e_ident[EI_ABIVERSION]);

    printf("Elf type:                               ");
    if (elf_ehdr->e_type == ET_NONE)
        printf("Unknown type\n");
    else if (elf_ehdr->e_type == ET_REL)
        printf("REL (Relocatable file)\n");
    else if (elf_ehdr->e_type == ET_EXEC)
        printf("EXEC (Executable file)\n");
    else if (elf_ehdr->e_type == ET_DYN)
        printf("DYN (Shared object file)\n");
    else if (elf_ehdr->e_type == ET_CORE)
        printf("CORE (Core file file)\n");

    print_emachine(elf_ehdr->e_machine);

    printf("Elf File Version:                       %d", elf_ehdr->e_version);
    if (elf_ehdr->e_version == EV_NONE)
        printf(" (Invalid Version)\n");
    else if (elf_ehdr->e_version == EV_CURRENT)
        printf(" (Current)\n");
    else
        printf(" (No fucking idea)\n");

    printf("Elf Program entry point:                0x%llx\n", (long long unsigned int)elf_ehdr->e_entry);
    printf("Elf Program header Offset:              %lld (raw offset bytes)\n", (long long unsigned int)elf_ehdr->e_phoff);
    printf("Elf Section header Offset:              %lld (raw offset bytes)\n", (long long unsigned int)elf_ehdr->e_shoff);
    printf("Elf processor flags:                    %lld\n", (long long unsigned int)elf_ehdr->e_flags);
    printf("Elf header's size:                      %lld (bytes)\n", (long long unsigned int)elf_ehdr->e_ehsize);
    printf("Elf program header entry size:          %lld (bytes)\n", (long long unsigned int)elf_ehdr->e_phentsize);
    printf("Elf program header number of entries:   %lld\n", (long long unsigned int)elf_ehdr->e_phnum);
    printf("Elf section header's size:              %lld (bytes)\n", (long long unsigned int)elf_ehdr->e_shentsize);
    printf("Elf section header number of entries:   %lld\n", (long long unsigned int)elf_ehdr->e_shnum);
    printf("Elf section header string table index:  %lld\n", (long long unsigned int)elf_ehdr->e_shstrndx);
}

/***
 * Program header parsing and printing
 */
int parse_elf_phdr(uint8_t *buf_ptr, size_t file_size)
{
    int i;
    Elf32_Phdr *elf32_phdr;
    Elf64_Phdr *elf64_phdr;

    if (buf_ptr == NULL)
    {
        fprintf(stderr, "parse_elf_phdr: cannot parse null buffer\n");
        return (-1);
    }

    if (elf_ehdr == NULL)
    {
        fprintf(stderr, "parse_elf_phdr: cannot parse program header without elf header\n");
        return (-1);
    }

    if (elf_phdr != NULL)
    {
        free_memory(elf_phdr);
        elf_phdr = NULL;
    }

    elf_phdr = allocate_memory(sizeof(Elf_Phdr) * elf_ehdr->e_phnum);

    if (is_32_bit_binary())
    {
        elf32_phdr = (Elf32_Phdr *)&buf_ptr[elf_ehdr->e_phoff];

        for (i = 0; i < elf_ehdr->e_phnum; i++)
        {
            elf_phdr[i].p_type = elf32_phdr[i].p_type;
            elf_phdr[i].p_flags = elf32_phdr[i].p_flags;
            elf_phdr[i].p_offset = elf32_phdr[i].p_offset;
            elf_phdr[i].p_vaddr = elf32_phdr[i].p_vaddr;
            elf_phdr[i].p_paddr = elf32_phdr[i].p_paddr;
            elf_phdr[i].p_filesz = elf32_phdr[i].p_filesz;
            elf_phdr[i].p_memsz = elf32_phdr[i].p_memsz;
            elf_phdr[i].p_align = elf32_phdr[i].p_align;
        }
    }
    else if (is_64_bit_binary())
    {
        elf64_phdr = (Elf64_Phdr *)&buf_ptr[elf_ehdr->e_phoff];

        for (i = 0; i < elf_ehdr->e_phnum; i++)
        {
            elf_phdr[i].p_type = elf64_phdr[i].p_type;
            elf_phdr[i].p_flags = elf64_phdr[i].p_flags;
            elf_phdr[i].p_offset = elf64_phdr[i].p_offset;
            elf_phdr[i].p_vaddr = elf64_phdr[i].p_vaddr;
            elf_phdr[i].p_paddr = elf64_phdr[i].p_paddr;
            elf_phdr[i].p_filesz = elf64_phdr[i].p_filesz;
            elf_phdr[i].p_memsz = elf64_phdr[i].p_memsz;
            elf_phdr[i].p_align = elf64_phdr[i].p_align;
        }
    }
    else
    {
        return (-1);
    }

    for (i = 0; i < elf_ehdr->e_phnum; i++)
    {
        if (elf_phdr[i].p_offset > file_size || (elf_phdr[i].p_offset + elf_phdr[i].p_filesz) > file_size)
        {
            fprintf(stderr, "parse_elf_phdr: program header %d is out of file bound\n", i);
            return (-1);
        }

        if (elf_phdr[i].p_type == PT_INTERP)
        {
            Interpreter = strdup((char *)&buf_ptr[elf_phdr[i].p_offset]);
        }
    }

    return (0);
}

static void
print_phdr_type(uint32_t type)
{
    switch (type)
    {
    case PT_NULL: // unused other members values are undefined
        printf("NULL\t\t");
        break;
    case PT_LOAD: // loadable segment described by p_filesz and p_memsz
        printf("LOAD\t\t");
        break;
    case PT_DYNAMIC: // dynamic linking information
        printf("DYNAMIC\t\t");
        break;
    case PT_INTERP: // location and size of null-terminated pathname to itnerpreter
        printf("INTERP\t\t");
        break;
    case PT_NOTE:
        printf("NOTE\t\t");
        break;
    case PT_SHLIB:
        printf("SHLIB\t\t");
        break;
    case PT_PHDR: // location and size of program header table
        printf("PHDR\t\t");
        break;
    case PT_LOPROC:
        printf("LOPROC\t\t");
        break;
    case PT_HIPROC:
        printf("HIPROC\t\t");
        break;
    case PT_GNU_EH_FRAME:
        printf("GNU_EH_FRAME\t");
        break;
    case PT_GNU_RELRO:
        printf("GNU_RELRO\t");
        break;
    case PT_GNU_STACK:
        printf("GNU_STACK\t");
        break;
    case PT_GNU_PROPERTY:
        printf("GNU_PROPERTY\t");
        break;
    case PT_OPENBSD_RANDOMIZE:
        printf("OPENBSD_RANDOMIZE\t");
        break;
    case PT_OPENBSD_WXNEEDED:
        printf("OPENBSD_WXNEEDED\t");
        break;
    case PT_OPENBSD_BOOTDATA:
        printf("OPENBSD_BOOTDATA\t");
        break;
    default:
        printf("%X\t\t", type);
        break;
    }
}

void print_elf_phdr()
{
    int i, j;

    printf("Elf Program Header:\n");

    printf("%s            %s%018s%018s\n%018s%018s%018s%018s\n\n", "TYPE", "FLAGS", "Offset", "V.Addr", "P.Addr", "F.Size", "M.Size", "Align");

    for (i = 0; i < elf_ehdr->e_phnum; i++)
    {
        print_phdr_type(elf_phdr[i].p_type);

        if (PF_R & elf_phdr[i].p_flags)
            printf("R");
        else
            printf(" ");

        if (PF_W & elf_phdr[i].p_flags)
            printf("W");
        else
            printf(" ");

        if (PF_X & elf_phdr[i].p_flags)
            printf("X");
        else
            printf(" ");

        printf("            0x%016llx 0x%016llx\n\t  0x%016llx 0x%016llx 0x%016llx 0x%llx",
               (long long unsigned int)elf_phdr[i].p_offset,
               (long long unsigned int)elf_phdr[i].p_vaddr,
               (long long unsigned int)elf_phdr[i].p_paddr,
               (long long unsigned int)elf_phdr[i].p_filesz,
               (long long unsigned int)elf_phdr[i].p_memsz,
               (long long unsigned int)elf_phdr[i].p_align);

        if (elf_phdr[i].p_type == PT_INTERP)
        {
            if (Interpreter)
            {
                printf("\n\t[Program Interpreter: %s]\n\n", Interpreter);
                free_memory(Interpreter);
            }
        }
        else if (elf_phdr[i].p_type == PT_LOAD)
        {
            if (PF_X & elf_phdr[i].p_flags)
            {
                printf("\t(TEXT)\n\n");
            }
            else
            {
                printf("\t(DATA)\n\n");
            }
        }
        else
        {
            printf("\n\n");
        }
    }

    printf("Mapping from section to segment: \n");
    printf("SEGMENT: SECTIONS\n");

    for (i = 0; i < elf_ehdr->e_phnum; i++)
    {
        printf("  %5d: ", i);

        for (j = 0; j < elf_ehdr->e_shnum; j++)
        {
            if (elf_shdr[j].sh_offset >= elf_phdr[i].p_offset && elf_shdr[j].sh_offset < (elf_phdr[i].p_offset + elf_phdr[i].p_filesz))
            {
                // if section is inside, just print name
                if (StringTable[elf_shdr[j].sh_name])
                {
                    printf("%s ", &StringTable[elf_shdr[j].sh_name]);
                }
            }
        }

        printf("\n");
    }
}

/***
 * Section header parsing and printing
 */
int parse_elf_shdr(uint8_t *buf_ptr, size_t file_size)
{
    int i;
    Elf32_Shdr *elf32_shdr;
    Elf64_Shdr *elf64_shdr;

    if (buf_ptr == NULL)
    {
        fprintf(stderr, "parse_elf_shdr: cannot parse null buffer\n");
        return (-1);
    }

    if (elf_ehdr == NULL)
    {
        fprintf(stderr, "parse_elf_shdr: cannot parse section header without elf header\n");
        return (-1);
    }

    if (elf_shdr != NULL)
    {
        free_memory(elf_shdr);
        elf_shdr = NULL;
    }

    elf_shdr = allocate_memory(sizeof(Elf_Shdr) * elf_ehdr->e_shnum);

    if (is_32_bit_binary())
    {
        elf32_shdr = (Elf32_Shdr *)&buf_ptr[elf_ehdr->e_shoff];

        for (i = 0; i < elf_ehdr->e_shnum; i++)
        {
            elf_shdr[i].sh_name = elf32_shdr[i].sh_name;
            elf_shdr[i].sh_type = elf32_shdr[i].sh_type;
            elf_shdr[i].sh_flags = elf32_shdr[i].sh_flags;
            elf_shdr[i].sh_addr = elf32_shdr[i].sh_addr;
            elf_shdr[i].sh_offset = elf32_shdr[i].sh_offset;
            elf_shdr[i].sh_size = elf32_shdr[i].sh_size;
            elf_shdr[i].sh_link = elf32_shdr[i].sh_link;
            elf_shdr[i].sh_info = elf32_shdr[i].sh_info;
            elf_shdr[i].sh_addralign = elf32_shdr[i].sh_addralign;
            elf_shdr[i].sh_entsize = elf32_shdr[i].sh_entsize;
        }
    }
    else if (is_64_bit_binary())
    {
        elf64_shdr = (Elf64_Shdr *)&buf_ptr[elf_ehdr->e_shoff];

        for (i = 0; i < elf_ehdr->e_shnum; i++)
        {
            elf_shdr[i].sh_name = elf64_shdr[i].sh_name;
            elf_shdr[i].sh_type = elf64_shdr[i].sh_type;
            elf_shdr[i].sh_flags = elf64_shdr[i].sh_flags;
            elf_shdr[i].sh_addr = elf64_shdr[i].sh_addr;
            elf_shdr[i].sh_offset = elf64_shdr[i].sh_offset;
            elf_shdr[i].sh_size = elf64_shdr[i].sh_size;
            elf_shdr[i].sh_link = elf64_shdr[i].sh_link;
            elf_shdr[i].sh_info = elf64_shdr[i].sh_info;
            elf_shdr[i].sh_addralign = elf64_shdr[i].sh_addralign;
            elf_shdr[i].sh_entsize = elf64_shdr[i].sh_entsize;
        }
    }
    else
    {
        return (-1);
    }

    for (i = 0; i < elf_ehdr->e_shnum; i++)
    {
        // only if section is present on disk
        //if ((elf_shdr[i].sh_type == SHT_PROGBITS) &&
        if ((elf_shdr[i].sh_type != SHT_NOBITS) &&
            ((elf_shdr[i].sh_offset > file_size) || ((elf_shdr[i].sh_offset + elf_shdr[i].sh_size) > file_size)))
        {
            fprintf(stderr, "parse_elf_shdr: section header %d is out of file bound\n", i);
            return (-1);
        }
    }

    // does anyone remember that e_shstrndx value? Is used for this
    if (elf_ehdr->e_shnum > elf_ehdr->e_shstrndx)
        StringTable = (char *)&buf_ptr[elf_shdr[elf_ehdr->e_shstrndx].sh_offset];

    return (0);
}

static void
print_16_str(char *string)
{
    int j;
    size_t string_length = strlen(string);

    for (j = 0; j < 16; j++)
    {
        if (j < string_length)
            printf("%c", string[j]);
        else
            printf(" ");
    }
    printf(" ");
}

static void
printf_shdr_type(uint32_t type)
{
    switch (type)
    {
    case SHT_NULL:
        print_16_str("NULL");
        break;
    case SHT_PROGBITS:
        print_16_str("PROGBITS");
        break;
    case SHT_SYMTAB:
        print_16_str("SYMTAB");
        break;
    case SHT_STRTAB:
        print_16_str("STRTAB");
        break;
    case SHT_RELA:
        print_16_str("RELA");
        break;
    case SHT_HASH:
        print_16_str("HASH");
        break;
    case SHT_DYNAMIC:
        print_16_str("DYNAMIC");
        break;
    case SHT_NOTE:
        print_16_str("NOTE");
        break;
    case SHT_NOBITS:
        print_16_str("NOBITS");
        break;
    case SHT_REL:
        print_16_str("REL");
        break;
    case SHT_SHLIB:
        print_16_str("SHLIB");
        break;
    case SHT_DYNSYM:
        print_16_str("DYNSYM");
        break;
    case SHT_LOPROC:
        print_16_str("LOPROC");
        break;
    case SHT_HIPROC:
        print_16_str("HIPROC");
        break;
    case SHT_LOUSER:
        print_16_str("LOUSER");
        break;
    case SHT_HIUSER:
        print_16_str("HIUSER");
        break;
    case SHT_GNU_ATTRIBUTES:
        print_16_str("GNU_ATTRIBUTES");
        break;
    case SHT_GNU_HASH:
        print_16_str("GNU_HASH");
        break;
    case SHT_GNU_LIBLIST:
        print_16_str("GNU_LIBLIST");
        break;
    case SHT_GNU_verdef:
        print_16_str("VERDEF");
        break;
    case SHT_GNU_verneed:
        print_16_str("VERNEED");
        break;
    case SHT_GNU_versym:
        print_16_str("VERSYM");
        break;
    case SHT_INIT_ARRAY:
        print_16_str("INIT_ARRAY");
        break;
    case SHT_FINI_ARRAY:
        print_16_str("FINI_ARRAY");
        break;
    case SHT_IA_64_UNWIND:
        print_16_str("IA_64_UNWIND");
        break;
    default:
        printf("%016x", type);
        break;
    }
}

static void
printf_shdr_flags(uint64_t flags)
{
    size_t i;
    int max = 16;

    if (flags & SHF_WRITE)
    {
        printf("W");
        max--;
    }

    if (flags & SHF_ALLOC)
    {
        printf("A");
        max--;
    }

    if (flags & SHF_EXECINSTR)
    {
        printf("X");
        max--;
    }

    if (flags & SHF_MERGE)
    {
        printf("M");
        max--;
    }

    if (flags & SHF_STRINGS)
    {
        printf("S");
        max--;
    }

    if (flags & SHF_INFO_LINK)
    {
        printf("I");
        max--;
    }

    if (flags & SHF_LINK_ORDER)
    {
        printf("L");
        max--;
    }

    if (flags & SHF_OS_NONCONFORMING)
    {
        printf("O");
        max--;
    }

    if (flags & SHF_GROUP)
    {
        printf("G");
        max--;
    }

    if (flags & SHF_TLS)
    {
        printf("T");
        max--;
    }

    if (flags & SHF_EXCLUDE)
    {
        printf("E");
    }

    if (flags & SHF_COMPRESSED)
    {
        printf("C");
    }

    for (i = 0; i < max; i++)
    {
        printf("-");
    }
}

void print_elf_shdr()
{
    int i;

    printf("Elf Section header:\n");

    printf("[ID] %07s%018s%18s%018s%018s\n%016s%018s%018s%018s%18s\n\n",
           "NAME", "TYPE", "FLAGS", "ADDRESS", "OFFSET",
           "SIZE", "LINK", "INFO", "ADDRALIGN", "ENTSIZE");

    for (i = 0; i < elf_ehdr->e_shnum; i++)
    {
        printf("[%02d] ", i);
        if (StringTable[elf_shdr[i].sh_name])
        {
            print_16_str(&StringTable[elf_shdr[i].sh_name]);
        }
        else
        {
            print_16_str("");
        }
        printf(" ");
        printf_shdr_type(elf_shdr[i].sh_type);
        printf(" ");
        printf_shdr_flags(elf_shdr[i].sh_flags);
        printf(" ");
        printf("%016x ", elf_shdr[i].sh_addr);
        printf("%016x ", elf_shdr[i].sh_offset);
        printf("\n%07s", " ");
        printf("%016x ", elf_shdr[i].sh_size);
        printf("%016x ", elf_shdr[i].sh_link);
        printf("%016x ", elf_shdr[i].sh_info);
        printf("%016x ", elf_shdr[i].sh_addralign);
        printf("%016x ", elf_shdr[i].sh_entsize);

        printf("\n\n");
    }
}

/***
 * Symbols header parsing and printing
 */
int parse_elf_sym(uint8_t *buf_ptr)
{
    Elf32_Sym *elf32_sym;
    Elf64_Sym *elf64_sym;
    Elf_Shdr *dynsym_sh = NULL;
    Elf_Shdr *symtab_sh = NULL;
    int i;

    if (buf_ptr == NULL)
    {
        fprintf(stderr, "parse_elf_sym: cannot parse null buffer\n");
        return (-1);
    }

    if (elf_ehdr == NULL)
    {
        fprintf(stderr, "parse_elf_sym: cannot parse symbol header without elf header\n");
        return (-1);
    }

    if (elf_shdr == NULL)
    {
        fprintf(stderr, "parse_elf_sym: cannot parse symbol header without section header\n");
        return (-1);
    }

    // get the section headers for symbols
    for (i = 0; i < elf_ehdr->e_shnum; i++)
    {
        if (elf_shdr[i].sh_type == SHT_DYNSYM)
        {
            dynsym_sh = &elf_shdr[i];

            /*
            *   The sh_link value of SHT_DYNSYM
            *   section points to the section
            *   of the strings for dynamic symbols.
            */
            if (elf_shdr[i].sh_link)
            {
                DynSymbolStringTable = (char *)&buf_ptr[elf_shdr[elf_shdr[i].sh_link].sh_offset];
            }
        }

        if (elf_shdr[i].sh_type == SHT_SYMTAB)
        {
            symtab_sh = &elf_shdr[i];

            /*
            *   The sh_link value of SHT_SYMTAB
            *   section points to the section
            *   of the strings for symbols.
            */
            if (elf_shdr[i].sh_link)
            {
                SymbolStringTable = (char *)&buf_ptr[elf_shdr[elf_shdr[i].sh_link].sh_offset];
            }
        }
    }

    // check if symbols contain something
    // in that case free memory
    if (elf_dynsym != NULL)
    {
        free_memory(elf_dynsym);
        elf_dynsym = NULL;
    }

    if (elf_symtab != NULL)
    {
        free_memory(elf_symtab);
        elf_symtab = NULL;
    }

    // .dynsym   This section holds the dynamic linking symbol table.
    if (dynsym_sh)
    {
        if (is_32_bit_binary())
        {
            dynsym_num = dynsym_sh->sh_size / sizeof(Elf32_Sym);

            elf_dynsym = (Elf_Sym *)allocate_memory(dynsym_num * sizeof(Elf_Sym));
            elf32_sym = (Elf32_Sym *)&buf_ptr[dynsym_sh->sh_offset];

            for (i = 0; i < dynsym_num; i++)
            {
                elf_dynsym[i].st_name = elf32_sym[i].st_name;
                elf_dynsym[i].st_info = elf32_sym[i].st_info;
                elf_dynsym[i].st_other = elf32_sym[i].st_other;
                elf_dynsym[i].st_shndx = elf32_sym[i].st_shndx;
                elf_dynsym[i].st_value = elf32_sym[i].st_value;
                elf_dynsym[i].st_size = elf32_sym[i].st_size;
            }
        }
        else if (is_64_bit_binary())
        {
            dynsym_num = dynsym_sh->sh_size / sizeof(Elf64_Sym);

            elf_dynsym = (Elf_Sym *)allocate_memory(dynsym_num * sizeof(Elf_Sym));
            elf64_sym = (Elf64_Sym *)&buf_ptr[dynsym_sh->sh_offset];

            for (i = 0; i < dynsym_num; i++)
            {
                elf_dynsym[i].st_name = elf64_sym[i].st_name;
                elf_dynsym[i].st_info = elf64_sym[i].st_info;
                elf_dynsym[i].st_other = elf64_sym[i].st_other;
                elf_dynsym[i].st_shndx = elf64_sym[i].st_shndx;
                elf_dynsym[i].st_value = elf64_sym[i].st_value;
                elf_dynsym[i].st_size = elf64_sym[i].st_size;
            }
        }
        else
        {
            return (-1);
        }
    }

    // .symtab   This section holds a symbol table.
    if (symtab_sh)
    {
        if (is_32_bit_binary())
        {
            symtab_num = symtab_sh->sh_size / sizeof(Elf32_Sym);

            elf_symtab = (Elf_Sym *)allocate_memory(symtab_num * sizeof(Elf_Sym));
            elf32_sym = (Elf32_Sym *)&buf_ptr[symtab_sh->sh_offset];

            for (i = 0; i < symtab_num; i++)
            {
                elf_symtab[i].st_name = elf32_sym[i].st_name;
                elf_symtab[i].st_info = elf32_sym[i].st_info;
                elf_symtab[i].st_other = elf32_sym[i].st_other;
                elf_symtab[i].st_shndx = elf32_sym[i].st_shndx;
                elf_symtab[i].st_value = elf32_sym[i].st_value;
                elf_symtab[i].st_size = elf32_sym[i].st_size;
            }
        }
        else if (is_64_bit_binary())
        {
            symtab_num = symtab_sh->sh_size / sizeof(Elf64_Sym);

            elf_symtab = (Elf_Sym *)allocate_memory(symtab_num * sizeof(Elf_Sym));
            elf64_sym = (Elf64_Sym *)&buf_ptr[symtab_sh->sh_offset];

            for (i = 0; i < symtab_num; i++)
            {
                elf_symtab[i].st_name = elf64_sym[i].st_name;
                elf_symtab[i].st_info = elf64_sym[i].st_info;
                elf_symtab[i].st_other = elf64_sym[i].st_other;
                elf_symtab[i].st_shndx = elf64_sym[i].st_shndx;
                elf_symtab[i].st_value = elf64_sym[i].st_value;
                elf_symtab[i].st_size = elf64_sym[i].st_size;
            }
        }
        else
        {
            return (-1);
        }
    }

    return (0);
}

static void
print_info(unsigned char st_info)
{
    uint64_t type, bind;

    if (is_32_bit_binary())
    {
        type = ELF32_ST_TYPE(st_info);
        bind = ELF32_ST_BIND(st_info);
    }
    else if (is_64_bit_binary())
    {
        type = ELF64_ST_TYPE(st_info);
        bind = ELF64_ST_BIND(st_info);
    }

    switch (type)
    {
    /*
    *   Type not specified
    */
    case STT_NOTYPE:
        printf("NOTYPE ");
        break;
    /*
    *   Symbol associated with a data object (variable, array, etc).
    */
    case STT_OBJECT:
        printf("OBJECT ");
        break;
    /*
    *   Symbol is associated with function or other executable
    *   code
    */
    case STT_FUNC:
        printf("FUNC   ");
        break;
    /*
    *   Symbol associated with a section. Symbol table entries of
    *   this type exist for relocation and normally have STB_LOCAL
    *   binding
    */
    case STT_SECTION:
        printf("SECTION");
        break;
    /*
    *   File symbol has STB_LOCAL binding, section index is SHN_ABS
    *   it precedes other STB_LOCAL symbol for file.
    */
    case STT_FILE:
        printf("FILE   ");
        break;
    case STT_LOPROC:
        printf("LOPROC ");
        break;
    case STT_HIPROC:
        printf("HIPROC ");
        break;
    default:
        printf("%08x", type);
        break;
    }
    printf(" ");

    switch (bind)
    {
    /* 
    *   local symbol, not visible outside object file containing definition,
    *   local symbols of same name can exist in multiple files without interfering
    *   with each other.
    */
    case STB_LOCAL:
        printf("LOCAL  ");
        break;
    /*
    *   Global symbols visible to all object files combined. One file's definition
    *   of a global symbol will satisfy another file's undefined reference to same
    *   global symbol.
    */
    case STB_GLOBAL:
        printf("GLOBAL ");
        break;
    /*
    *   Resemble global symbols, but definitions have lower precedence
    */
    case STB_WEAK:
        printf("WEAK   ");
        break;
    default:
        printf("%08x", bind);
        break;
    }
    printf(" ");
}

static void
print_visibility(unsigned char st_other)
{
    uint64_t visibility;

    if (is_32_bit_binary())
        visibility = ELF32_ST_VISIBILITY(st_other);
    else if (is_64_bit_binary())
        visibility = ELF64_ST_VISIBILITY(st_other);

    switch (visibility)
    {
    case STV_DEFAULT:
        printf("DEFAULT  ");
        break;
    case STV_INTERNAL:
        printf("INTERNAL ");
        break;
    case STV_HIDDEN:
        printf("HIDDEN   ");
        break;
    case STV_PROTECTED:
        printf("PROTECTED");
        break;
    default:
        printf("%08x  ", visibility);
        break;
    }
    printf(" ");
}

static void
print_section(uint16_t section)
{
    /*
    *   Symbol has absolute value, will not change
    *   because of relocation.
    */
    if (section == SHN_ABS)
        printf("%2sABS", " ");
    /*
    *   Symbol undefined, link editor combines this
    *   object file with another that defines
    *   indicated symbol, file's references to symbol
    *   will be linked to actual definition
    */
    else if (section == SHN_UNDEF)
        printf("%2sUND", " ");
    else if (section == SHN_BEFORE)
        printf("%2sBEF", " ");
    else if (section == SHN_AFTER)
        printf("%2sAFT", " ");
    else
        printf("%5d", section);

    printf(" ");
}

void print_elf_sym()
{
    int i;

    printf("Elf symbol headers:\n");

    if (elf_dynsym)
    {
        printf("Found .dynsym section symbols with %d symbols\n", dynsym_num);

        printf("   %s:      %s            %s        %s    %s   %s     %s %s\n",
               "ID", "Value", "Size", "TYPE", "UNION", "VIS", "Section", "NAME");

        for (i = 0; i < dynsym_num; i++)
        {
            printf(" %4d: %016x %016x ", i, elf_dynsym[i].st_value, elf_dynsym[i].st_size);
            print_info(elf_dynsym[i].st_info);
            print_visibility(elf_dynsym[i].st_other);
            print_section(elf_dynsym[i].st_shndx);
            if (elf_dynsym[i].st_name != 0)
            {
                if (&DynSymbolStringTable[elf_dynsym[i].st_name])
                    printf("%s", &DynSymbolStringTable[elf_dynsym[i].st_name]);
            }
            printf("\n");
        }
    }

    if (elf_symtab)
    {
        printf("Found .symtab section symbols with %d symbols\n", symtab_num);

        printf("   %s:      %s            %s        %s    %s   %s     %s %s\n",
               "ID", "Value", "Size", "TYPE", "UNION", "VIS", "Section", "NAME");

        for (i = 0; i < symtab_num; i++)
        {
            printf(" %4d: %016x %016x ", i, elf_symtab[i].st_value, elf_symtab[i].st_size);
            print_info(elf_symtab[i].st_info);
            print_visibility(elf_symtab[i].st_other);
            print_section(elf_symtab[i].st_shndx);
            if (elf_symtab[i].st_name != 0)
            {
                if (&SymbolStringTable[elf_symtab[i].st_name])
                    printf("%s", &SymbolStringTable[elf_symtab[i].st_name]);
            }
            printf("\n");
        }
    }
}

/***
 * Relocation header parsing and printing
 */

int parse_elf_rel_a(uint8_t *buf_ptr, size_t file_size)
{
    size_t section_relocs_i;
    int i, j;
    size_t rel_index = 0, rela_index = 0;

    Elf32_Rel *elf32_rel;
    Elf64_Rel *elf64_rel;
    Elf32_Rela *elf32_rela;
    Elf64_Rela *elf64_rela;

    if (buf_ptr == NULL)
    {
        fprintf(stderr, "parse_elf_rel_a: cannot parse null buffer\n");
        return (-1);
    }

    if (elf_ehdr == NULL)
    {
        fprintf(stderr, "parse_elf_rel_a: cannot parse reloc header without elf header\n");
        return (-1);
    }

    if (elf_shdr == NULL)
    {
        fprintf(stderr, "parse_elf_rel_a: cannot parse reloc header without section header\n");
        return (-1);
    }

    // first let's see if there are REL and RELA sections already
    if (elf_rel != NULL)
    {
        for (i = 0; i < rel_sections; i++)
        {
            free_memory(elf_rel[i]);
            elf_rel[i] = NULL;
        }
        free_memory(elf_rel);
        elf_rel = NULL;

        rel_sections = 0;
    }

    if (elf_rela != NULL)
    {
        for (i = 0; i < rela_sections; i++)
        {
            free_memory(elf_rela[i]);
            elf_rela[i] = NULL;
        }
        free_memory(elf_rela);
        elf_rela = NULL;

        rela_sections = 0;
    }

    // Now count again number of rel and rela sections
    for (i = 0; i < elf_ehdr->e_shnum; i++)
    {
        if (elf_shdr[i].sh_type == SHT_REL)
            rel_sections++;
        else if (elf_shdr[i].sh_type == SHT_RELA)
            rela_sections++;
    }

    if (rel_sections)
        elf_rel = allocate_memory(rel_sections * sizeof(Elf_Rel *));

    if (rela_sections)
        elf_rela = allocate_memory(rela_sections * sizeof(Elf_Rela *));

    for (i = 0; i < elf_ehdr->e_shnum; i++)
    {
        if (elf_shdr[i].sh_type == SHT_REL)
        {
            if (is_32_bit_binary())
            {
                elf32_rel = (Elf32_Rel *)&buf_ptr[elf_shdr[i].sh_offset];

                section_relocs_i = elf_shdr[i].sh_size / sizeof(Elf32_Rel);

                if (section_relocs_i)
                    elf_rel[rel_index] = allocate_memory(section_relocs_i * sizeof(Elf_Rel));

                for (j = 0; j < section_relocs_i; j++)
                {
                    elf_rel[rel_index][j].r_info = elf32_rel[j].r_info;
                    elf_rel[rel_index][j].r_offset = elf32_rel[j].r_offset;
                }
            }
            else if (is_64_bit_binary())
            {
                elf64_rel = (Elf64_Rel *)&buf_ptr[elf_shdr[i].sh_offset];

                section_relocs_i = elf_shdr[i].sh_size / sizeof(Elf64_Rel);

                if (section_relocs_i)
                    elf_rel[rel_index] = allocate_memory(section_relocs_i * sizeof(Elf_Rel));

                for (j = 0; j < section_relocs_i; j++)
                {
                    elf_rel[rel_index][j].r_info = elf64_rel[j].r_info;
                    elf_rel[rel_index][j].r_offset = elf64_rel[j].r_offset;
                }
            }
            rel_index++;
        }

        if (elf_shdr[i].sh_type == SHT_RELA)
        {
            if (is_32_bit_binary())
            {
                elf32_rela = (Elf32_Rela *)&buf_ptr[elf_shdr[i].sh_offset];

                section_relocs_i = elf_shdr[i].sh_size / sizeof(Elf32_Rela);

                if (section_relocs_i)
                    elf_rela[rela_index] = allocate_memory(section_relocs_i * sizeof(Elf_Rela));

                for (j = 0; j < section_relocs_i; j++)
                {
                    elf_rela[rela_index][j].r_info = elf32_rela[j].r_info;
                    elf_rela[rela_index][j].r_offset = elf32_rela[j].r_offset;
                    elf_rela[rela_index][j].r_addend = elf32_rela[j].r_addend;
                }
            }
            else if (is_64_bit_binary())
            {
                elf64_rela = (Elf64_Rela *)&buf_ptr[elf_shdr[i].sh_offset];

                section_relocs_i = elf_shdr[i].sh_size / sizeof(Elf64_Rela);

                if (section_relocs_i)
                    elf_rela[rela_index] = allocate_memory(section_relocs_i * sizeof(Elf_Rela));

                for (j = 0; j < section_relocs_i; j++)
                {
                    elf_rela[rela_index][j].r_info = elf64_rela[j].r_info;
                    elf_rela[rela_index][j].r_offset = elf64_rela[j].r_offset;
                    elf_rela[rela_index][j].r_addend = elf64_rela[j].r_addend;
                }
            }

            rela_index++;
        }
    }

    return (0);
}

static void
print_rel_info_32_bit(uint64_t r_info, Elf_Sym *associated_symbol, char *str_table)
{
    uint64_t sym = ELF32_R_SYM(r_info);
    uint64_t type = ELF32_R_TYPE(r_info);

    printf(" ");

    switch (type)
    {
    case R_386_NONE:
        printf("%-18s", "R_386_NONE");
        break;
    case R_386_32:
        printf("%-18s", "R_386_32");
        break;
    case R_386_PC32:
        printf("%-18s", "R_386_PC32");
        break;
    case R_386_GOT32:
        printf("%-18s", "R_386_GOT32");
        break;
    case R_386_PLT32:
        printf("%-18s", "R_386_PLT32");
        break;
    case R_386_COPY:
        printf("%-18s", "R_386_COPY");
        break;
    case R_386_GLOB_DAT:
        printf("%-18s", "R_386_GLOB_DAT");
        break;
    case R_386_JMP_SLOT:
        printf("%-18s", "R_386_JMP_SLOT");
        break;
    case R_386_RELATIVE:
        printf("%-18s", "R_386_RELATIVE");
        break;
    case R_386_GOTOFF:
        printf("%-18s", "R_386_GOTOFF");
        break;
    case R_386_GOTPC:
        printf("%-18s", "R_386_GOTPC");
        break;
    case R_386_32PLT:
        printf("%-18s", "R_386_32PLT");
        break;
    case R_386_TLS_TPOFF:
        printf("%-18s", "R_386_TLS_TPOFF");
        break;
    case R_386_TLS_IE:
        printf("%-18s", "R_386_TLS_IE");
        break;
    case R_386_TLS_GOTIE:
        printf("%-18s", "R_386_TLS_GOTIE");
        break;
    case R_386_TLS_LE:
        printf("%-18s", "R_386_TLS_LE");
        break;
    case R_386_TLS_GD:
        printf("%-18s", "R_386_TLS_GD");
        break;
    case R_386_TLS_LDM:
        printf("%-18s", "R_386_TLS_LDM");
        break;
    case R_386_16:
        printf("%-18s", "R_386_16");
        break;
    case R_386_PC16:
        printf("%-18s", "R_386_PC16");
        break;
    case R_386_8:
        printf("%-18s", "R_386_8");
        break;
    case R_386_PC8:
        printf("%-18s", "R_386_PC8");
        break;
    case R_386_TLS_GD_32:
        printf("%-18s", "R_386_TLS_GD_32");
        break;
    case R_386_TLS_GD_PUSH:
        printf("%-18s", "R_386_TLS_GD_PUSH");
        break;
    case R_386_TLS_GD_CALL:
        printf("%-18s", "R_386_TLS_GD_CALL");
        break;
    case R_386_TLS_GD_POP:
        printf("%-18s", "R_386_TLS_GD_POP");
        break;
    case R_386_TLS_LDM_32:
        printf("%-18s", "R_386_TLS_LDM_32");
        break;
    case R_386_TLS_LDM_PUSH:
        printf("%-18s", "R_386_TLS_LDM_PUSH");
        break;
    case R_386_TLS_LDM_CALL:
        printf("%-18s", "R_386_TLS_LDM_CALL");
        break;
    case R_386_TLS_LDM_POP:
        printf("%-18s", "R_386_TLS_LDM_POP");
        break;
    case R_386_TLS_LDO_32:
        printf("%-18s", "R_386_TLS_LDO_32");
        break;
    case R_386_TLS_IE_32:
        printf("%-18s", "R_386_TLS_IE_32");
        break;
    case R_386_TLS_LE_32:
        printf("%-18s", "R_386_TLS_LE_32");
        break;
    case R_386_TLS_DTPMOD32:
        printf("%-18s", "R_386_TLS_DTPMOD32");
        break;
    case R_386_TLS_DTPOFF32:
        printf("%-18s", "R_386_TLS_DTPOFF32");
        break;
    case R_386_TLS_TPOFF32:
        printf("%-18s", "R_386_TLS_TPOFF32");
        break;
    case R_386_SIZE32:
        printf("%-18s", "R_386_SIZE32");
        break;
    case R_386_TLS_GOTDESC:
        printf("%-18s", "R_386_TLS_GOTDESC");
        break;
    case R_386_TLS_DESC_CALL:
        printf("%-18s", "R_386_TLS_DESC_CALL");
        break;
    case R_386_TLS_DESC:
        printf("%-18s", "R_386_TLS_DESC");
        break;
    case R_386_IRELATIVE:
        printf("%-18s", "R_386_IRELATIVE");
        break;
    case R_386_GOT32X:
        printf("%-18s", "R_386_GOT32X");
        break;
    case R_386_NUM:
        printf("%-18s", "R_386_NUM");
        break;
    default:
        printf("%016x", type);
        break;
    }

    if (associated_symbol[sym].st_name && &str_table[associated_symbol[sym].st_name])
        printf(" %016x %s", associated_symbol[sym].st_value, &str_table[associated_symbol[sym].st_name]);
    else
        printf(" %016x", associated_symbol[sym].st_value);
}

static void
print_rel_info_64_bit(uint64_t r_info, Elf_Sym *associated_symbol, char *str_table)
{
    uint64_t sym = ELF64_R_SYM(r_info);
    uint64_t type = ELF64_R_TYPE(r_info);

    printf(" ");

    switch (type)
    {
    case R_X86_64_NONE:
        printf("%-18s", "R_X86_64_NONE");
        break;
    case R_X86_64_64:
        printf("%-18s", "R_X86_64_64");
        break;
    case R_X86_64_PC32:
        printf("%-18s", "R_X86_64_PC32");
        break;
    case R_X86_64_GOT32:
        printf("%-18s", "R_X86_64_GOT32");
        break;
    case R_X86_64_PLT32:
        printf("%-18s", "R_X86_64_PLT32");
        break;
    case R_X86_64_COPY:
        printf("%-18s", "R_X86_64_COPY");
        break;
    case R_X86_64_GLOB_DAT:
        printf("%-18s", "R_X86_64_GLOB_DAT");
        break;
    case R_X86_64_JUMP_SLOT:
        printf("%-18s", "R_X86_64_JUMP_SLOT");
        break;
    case R_X86_64_RELATIVE:
        printf("%-18s", "R_X86_64_RELATIVE");
        break;
    case R_X86_64_GOTPCREL:
        printf("%-18s", "R_X86_64_GOTPCREL");
        break;
    case R_X86_64_32:
        printf("%-18s", "R_X86_64_32");
        break;
    case R_X86_64_32S:
        printf("%-18s", "R_X86_64_32S");
        break;
    case R_X86_64_16:
        printf("%-18s", "R_X86_64_16");
        break;
    case R_X86_64_PC16:
        printf("%-18s", "R_X86_64_PC16");
        break;
    case R_X86_64_8:
        printf("%-18s", "R_X86_64_8");
        break;
    case R_X86_64_PC8:
        printf("%-18s", "R_X86_64_PC8");
        break;
    case R_X86_64_DTPMOD64:
        printf("%-18s", "R_X86_64_DTPMOD64");
        break;
    case R_X86_64_DTPOFF64:
        printf("%-18s", "R_X86_64_DTPOFF64");
        break;
    case R_X86_64_TPOFF64:
        printf("%-18s", "R_X86_64_TPOFF64");
        break;
    case R_X86_64_TLSGD:
        printf("%-18s", "R_X86_64_TLSGD");
        break;
    case R_X86_64_TLSLD:
        printf("%-18s", "R_X86_64_TLSLD");
        break;
    case R_X86_64_DTPOFF32:
        printf("%-18s", "R_X86_64_DTPOFF32");
        break;
    case R_X86_64_GOTTPOFF:
        printf("%-18s", "R_X86_64_GOTTPOFF");
        break;
    case R_X86_64_TPOFF32:
        printf("%-18s", "R_X86_64_TPOFF32");
        break;
    case R_X86_64_PC64:
        printf("%-18s", "R_X86_64_PC64");
        break;
    case R_X86_64_GOTOFF64:
        printf("%-18s", "R_X86_64_GOTOFF64");
        break;
    case R_X86_64_GOTPC32:
        printf("%-18s", "R_X86_64_GOTPC32");
        break;
    case R_X86_64_GOT64:
        printf("%-18s", "R_X86_64_GOT64");
        break;
    case R_X86_64_GOTPCREL64:
        printf("%-18s", "R_X86_64_GOTPCREL64");
        break;
    case R_X86_64_GOTPC64:
        printf("%-18s", "R_X86_64_GOTPC64");
        break;
    case R_X86_64_GOTPLT64:
        printf("%-18s", "R_X86_64_GOTPLT64");
        break;
    case R_X86_64_PLTOFF64:
        printf("%-18s", "R_X86_64_PLTOFF64");
        break;
    case R_X86_64_SIZE32:
        printf("%-18s", "R_X86_64_SIZE32");
        break;
    case R_X86_64_SIZE64:
        printf("%-18s", "R_X86_64_SIZE64");
        break;
    case R_X86_64_GOTPC32_TLSDESC:
        printf("%-18s", "R_X86_64_GOTPC32_TLSDESC");
        break;
    case R_X86_64_TLSDESC_CALL:
        printf("%-18s", "R_X86_64_TLSDESC_CALL");
        break;
    case R_X86_64_TLSDESC:
        printf("%-18s", "R_X86_64_TLSDESC");
        break;
    case R_X86_64_IRELATIVE:
        printf("%-18s", "R_X86_64_IRELATIVE");
        break;
    case R_X86_64_RELATIVE64:
        printf("%-18s", "R_X86_64_RELATIVE64");
        break;
    case R_X86_64_GOTPCRELX:
        printf("%-18s", "R_X86_64_GOTPCRELX");
        break;
    case R_X86_64_REX_GOTPCRELX:
        printf("%-18s", "R_X86_64_REX_GOTPCRELX");
        break;
    case R_X86_64_NUM:
        printf("%-18s", "R_X86_64_NUM");
        break;
    default:
        printf("%016x", type);
        break;
    }

    if (associated_symbol[sym].st_name && &str_table[associated_symbol[sym].st_name])
        printf(" %016x %s", associated_symbol[sym].st_value, &str_table[associated_symbol[sym].st_name]);
    else
        printf(" %016x", associated_symbol[sym].st_value);
}

static void
print_rel_info(uint64_t r_info, Elf_Sym *associated_symbol, char *str_table)
{
    if (is_32_bit_binary())
    {
        print_rel_info_32_bit(r_info, associated_symbol, str_table);
    }
    else if (is_64_bit_binary())
    {
        print_rel_info_64_bit(r_info, associated_symbol, str_table);
    }
    else
    {
        printf(" (not supported binary architecture)");
    }
}

void print_elf_rel_a()
{
    int i, j;
    size_t rel_index = 0, rela_index = 0;
    size_t section_relocs_i;
    Elf_Sym *associated_symbol;
    char *str_table;

    printf("Elf reloc headers:\n");
    for (i = 0; i < elf_ehdr->e_shnum; i++)
    {
        if (elf_shdr[i].sh_type == SHT_REL)
        {
            if (is_32_bit_binary())
            {
                section_relocs_i = elf_shdr[i].sh_size / sizeof(Elf32_Rel);
            }
            else if (is_64_bit_binary())
            {
                section_relocs_i = elf_shdr[i].sh_size / sizeof(Elf64_Rel);
            }

            if (StringTable[elf_shdr[i].sh_name])
                printf("Found reloc section %s, relocs (%d):\n\n", &StringTable[elf_shdr[i].sh_name], section_relocs_i);
            else
                printf("Found reloc section %s, relocs (%d):\n\n", "NONE", section_relocs_i);

            printf("[%3s] %8s %16s %17s %19s %17s\n", "ID", "OFFSET", "INFO", "REL. TYPE", "SYM. VALUE", "Symbol Name");

            if (elf_shdr[elf_shdr[i].sh_link].sh_type == SHT_DYNSYM)
            {
                associated_symbol = elf_dynsym;
                str_table = DynSymbolStringTable;
            }
            else if (elf_shdr[elf_shdr[i].sh_link].sh_type == SHT_SYMTAB)
            {
                associated_symbol = elf_symtab;
                str_table = SymbolStringTable;
            }

            for (j = 0; j < section_relocs_i; j++)
            {
                printf("[%3d] %016x %016x", j, elf_rel[rel_index][j].r_offset, elf_rel[rel_index][j].r_info);
                print_rel_info(elf_rel[rel_index][j].r_info, associated_symbol, str_table);
                printf("\n");
            }

            rel_index++;
            printf("\n");
        }

        if (elf_shdr[i].sh_type == SHT_RELA)
        {
            if (is_32_bit_binary())
            {
                section_relocs_i = elf_shdr[i].sh_size / sizeof(Elf32_Rela);
            }
            else if (is_64_bit_binary())
            {
                section_relocs_i = elf_shdr[i].sh_size / sizeof(Elf64_Rela);
            }

            if (StringTable[elf_shdr[i].sh_name])
                printf("Found reloc section %s, relocs (%d):\n\n", &StringTable[elf_shdr[i].sh_name], section_relocs_i);
            else
                printf("Found reloc section %s, relocs (%d):\n\n", "NONE", section_relocs_i);

            printf("[%3s] %8s %16s %16s %17s %19s %17s\n", "ID", "OFFSET", "INFO", "ADDEND", "REL. TYPE", "SYM. VALUE", "Symbol Name");

            if (elf_shdr[elf_shdr[i].sh_link].sh_type == SHT_DYNSYM)
            {
                associated_symbol = elf_dynsym;
                str_table = DynSymbolStringTable;
            }
            else if (elf_shdr[elf_shdr[i].sh_link].sh_type == SHT_SYMTAB)
            {
                associated_symbol = elf_symtab;
                str_table = SymbolStringTable;
            }

            for (j = 0; j < section_relocs_i; j++)
            {
                printf("[%3d] %016x %016x %016x", j, elf_rela[rela_index][j].r_offset, elf_rela[rela_index][j].r_info, elf_rela[rela_index][j].r_addend);
                print_rel_info(elf_rela[rela_index][j].r_info, associated_symbol, str_table);
                printf("\n");
            }

            rela_index++;
            printf("\n");
        }
    }
}

/***
 * Dynamic program header parsing and printing
 */
int parse_elf_dynamic(uint8_t *buf_ptr, size_t file_size)
{
    int i;

    Elf32_Dyn *elf32_dyn;
    Elf64_Dyn *elf64_dyn;

    Elf_Phdr *dynamic;

    if (buf_ptr == NULL)
    {
        fprintf(stderr, "parse_elf_dynamic: cannot parse null buffer\n");
        return (-1);
    }

    if (elf_ehdr == NULL)
    {
        fprintf(stderr, "parse_elf_dynamic: cannot parse dynamic program header without elf header\n");
        return (-1);
    }

    if (elf_phdr == NULL)
    {
        fprintf(stderr, "parse_elf_dynamic: cannot parse dynamic program header without elf program header\n");
        return (-1);
    }

    // first let's see if there are dynamic headers already
    if (elf_dyn != NULL)
    {
        free_memory(elf_dyn);
        elf_dyn = NULL;

        dynamic_headers = 0;
    }
    // Now get number of dynamic headers
    for (i = 0; i < elf_ehdr->e_phnum; i++)
    {
        if (elf_phdr[i].p_type == PT_DYNAMIC)
        {
            if (is_32_bit_binary())
            {
                dynamic_headers = elf_phdr[i].p_filesz / sizeof(Elf32_Dyn);
            }
            else if (is_64_bit_binary())
            {
                dynamic_headers = elf_phdr[i].p_filesz / sizeof(Elf64_Dyn);
            }

            dynamic = &elf_phdr[i];

            break;
        }
    }

    if (dynamic_headers)
    {
        elf_dyn = allocate_memory(dynamic_headers * sizeof(Elf_Dyn));
    }

    if (is_32_bit_binary())
    {
        elf32_dyn = (Elf32_Dyn *)&buf_ptr[dynamic->p_offset];
    }
    else if (is_64_bit_binary())
    {
        elf64_dyn = (Elf64_Dyn *)&buf_ptr[dynamic->p_offset];
    }

    for (i = 0; i < dynamic_headers; i++)
    {
        if (is_32_bit_binary())
        {
            elf_dyn[i].d_tag = elf32_dyn[i].d_tag;
            elf_dyn[i].d_un.d_ptr = elf32_dyn[i].d_un.d_ptr;
        }
        else if (is_64_bit_binary())
        {
            elf_dyn[i].d_tag = elf64_dyn[i].d_tag;
            elf_dyn[i].d_un.d_ptr = elf64_dyn[i].d_un.d_ptr;
        }
    }

    return (0);
}

static char *
print_tag(Elf64_Sxword d_tag)
{
    char *ret_value;
    switch (d_tag)
    {
    case DT_NULL:
        ret_value = "DT_NULL";
        break;
    case DT_NEEDED:
        ret_value = "DT_NEEDED";
        break;
    case DT_PLTRELSZ:
        ret_value = "DT_PLTRELSZ";
        break;
    case DT_PLTGOT:
        ret_value = "DT_PLTGOT";
        break;
    case DT_HASH:
        ret_value = "DT_HASH";
        break;
    case DT_STRTAB:
        ret_value = "DT_STRTAB";
        break;
    case DT_SYMTAB:
        ret_value = "DT_SYMTAB";
        break;
    case DT_RELA:
        ret_value = "DT_RELA";
        break;
    case DT_RELASZ:
        ret_value = "DT_RELASZ";
        break;
    case DT_RELAENT:
        ret_value = "DT_RELAENT";
        break;
    case DT_STRSZ:
        ret_value = "DT_STRSZ";
        break;
    case DT_SYMENT:
        ret_value = "DT_SYMENT";
        break;
    case DT_INIT:
        ret_value = "DT_INIT";
        break;
    case DT_FINI:
        ret_value = "DT_FINI";
        break;
    case DT_SONAME:
        ret_value = "DT_SONAME";
        break;
    case DT_RPATH:
        ret_value = "DT_RPATH";
        break;
    case DT_SYMBOLIC:
        ret_value = "DT_SYMBOLIC";
        break;
    case DT_REL:
        ret_value = "DT_REL";
        break;
    case DT_RELSZ:
        ret_value = "DT_RELSZ";
        break;
    case DT_RELENT:
        ret_value = "DT_RELENT";
        break;
    case DT_PLTREL:
        ret_value = "DT_PLTREL";
        break;
    case DT_DEBUG:
        ret_value = "DT_DEBUG";
        break;
    case DT_TEXTREL:
        ret_value = "DT_TEXTREL";
        break;
    case DT_JMPREL:
        ret_value = "DT_JMPREL";
        break;
    case DT_BIND_NOW:
        ret_value = "DT_BIND_NOW";
        break;
    case DT_INIT_ARRAY:
        ret_value = "DT_INIT_ARRAY";
        break;
    case DT_FINI_ARRAY:
        ret_value = "DT_FINI_ARRAY";
        break;
    case DT_INIT_ARRAYSZ:
        ret_value = "DT_INIT_ARRAYSZ";
        break;
    case DT_FINI_ARRAYSZ:
        ret_value = "DT_FINI_ARRAYSZ";
        break;
    case DT_RUNPATH:
        ret_value = "DT_RUNPATH";
        break;
    case DT_FLAGS:
        ret_value = "DT_FLAGS";
        break;
    case DT_ENCODING:
        ret_value = "DT_ENCODING";
        break;
    case DT_PREINIT_ARRAYSZ:
        ret_value = "DT_PREINIT_ARRAYSZ";
        break;
    case DT_SYMTAB_SHNDX:
        ret_value = "DT_SYMTAB_SHNDX";
        break;
    case DT_NUM:
        ret_value = "DT_NUM";
        break;
    case DT_LOOS:
        ret_value = "DT_LOOS";
        break;
    case DT_HIOS:
        ret_value = "DT_HIOS";
        break;
    case DT_LOPROC:
        ret_value = "DT_LOPROC";
        break;
    case DT_HIPROC:
        ret_value = "DT_HIPROC";
        break;
    case DT_VALRNGLO:
        ret_value = "DT_VALRNGLO";
        break;
    case DT_GNU_PRELINKED:
        ret_value = "DT_GNU_PRELINKED";
        break;
    case DT_GNU_CONFLICTSZ:
        ret_value = "DT_GNU_CONFLICTSZ";
        break;
    case DT_GNU_LIBLISTSZ:
        ret_value = "DT_GNU_LIBLISTSZ";
        break;
    case DT_CHECKSUM:
        ret_value = "DT_CHECKSUM";
        break;
    case DT_PLTPADSZ:
        ret_value = "DT_PLTPADSZ";
        break;
    case DT_MOVEENT:
        ret_value = "DT_MOVEENT";
        break;
    case DT_MOVESZ:
        ret_value = "DT_MOVESZ";
        break;
    case DT_FEATURE_1:
        ret_value = "DT_FEATURE_1";
        break;
    case DT_POSFLAG_1:
        ret_value = "DT_POSFLAG_1";
        break;
    case DT_SYMINSZ:
        ret_value = "DT_SYMINSZ";
        break;
    case DT_SYMINENT:
        ret_value = "DT_SYMINENT";
        break;
    case DT_ADDRRNGLO:
        ret_value = "DT_ADDRRNGLO";
        break;
    case DT_GNU_HASH:
        ret_value = "DT_GNU_HASH";
        break;
    case DT_TLSDESC_PLT:
        ret_value = "DT_TLSDESC_PLT";
        break;
    case DT_TLSDESC_GOT:
        ret_value = "DT_TLSDESC_GOT";
        break;
    case DT_GNU_CONFLICT:
        ret_value = "DT_GNU_CONFLICT";
        break;
    case DT_GNU_LIBLIST:
        ret_value = "DT_GNU_LIBLIST";
        break;
    case DT_CONFIG:
        ret_value = "DT_CONFIG";
        break;
    case DT_DEPAUDIT:
        ret_value = "DT_DEPAUDIT";
        break;
    case DT_AUDIT:
        ret_value = "DT_AUDIT";
        break;
    case DT_PLTPAD:
        ret_value = "DT_PLTPAD";
        break;
    case DT_MOVETAB:
        ret_value = "DT_MOVETAB";
        break;
    case DT_SYMINFO:
        ret_value = "DT_SYMINFO";
        break;
    case DT_VERSYM:
        ret_value = "DT_VERSYM";
        break;
    case DT_RELACOUNT:
        ret_value = "DT_RELACOUNT";
        break;
    case DT_RELCOUNT:
        ret_value = "DT_RELCOUNT";
        break;
    case DT_FLAGS_1:
        ret_value = "DT_FLAGS_1";
        break;
    case DT_VERDEF:
        ret_value = "DT_VERDEF";
        break;
    case DT_VERDEFNUM:
        ret_value = "DT_VERDEFNUM";
        break;
    case DT_VERNEED:
        ret_value = "DT_VERNEED";
        break;
    case DT_VERNEEDNUM:
        ret_value = "DT_VERNEEDNUM";
        break;
    case DT_AUXILIARY:
        ret_value = "DT_AUXILIARY";
        break;
    default:
        ret_value = NULL;
        break;
    }

    return ret_value;
}

void print_elf_dynamic()
{
    int i;

    printf("Elf Dynamic Program Header:\n");

    printf("   %s: %016s %s %09s %016s\n",
           "ID", "TAG", "TAG STR", "", "Val/Ptr");
    for (i = 0; i < dynamic_headers; i++)
    {
        char *tag = print_tag(elf_dyn[i].d_tag);

        if (tag == NULL)
            printf(" %4d: %016x %016s %016x", i, elf_dyn[i].d_tag, " ", elf_dyn[i].d_un.d_ptr);
        else
            printf(" %4d: %016x %-016s %016x", i, elf_dyn[i].d_tag, tag, elf_dyn[i].d_un.d_ptr);

        if (elf_dyn[i].d_tag == DT_NEEDED)
        {
            if ((Interpreter != NULL) && (strcmp(Interpreter, &DynSymbolStringTable[elf_dyn[i].d_un.d_val]) == 0))
                printf(" [Program Interpreter: %s]", &DynSymbolStringTable[elf_dyn[i].d_un.d_val]);
            else
                printf(" [Shared Lib: %s]", &DynSymbolStringTable[elf_dyn[i].d_un.d_val]);
        }
        else if (elf_dyn[i].d_tag == DT_SONAME)
        {
            printf(" [Exported Library: %s]", &DynSymbolStringTable[elf_dyn[i].d_un.d_val]);
        }

        printf("\n");
    }
}

void 
print_imported_libraries()
{
    int i, j = 0;

    printf("Elf binary imported libraries:\n");

    printf("   %s: %s\n",
           "ID", "Name");

    for (i = 0; i < dynamic_headers; i++)
    {
        if (elf_dyn[i].d_tag == DT_NEEDED)
        {
            if (!Interpreter || strcmp(Interpreter, &DynSymbolStringTable[elf_dyn[i].d_un.d_val]) != 0)
                printf(" %4d: %s\n", j++, &DynSymbolStringTable[elf_dyn[i].d_un.d_val]);
        }
    }

    return;
}

void 
print_imported_functions()
{
    int i, j = 0;
    uint64_t type;

    printf("Elf imported functions:\n");

    printf("   %s: %s\n",
           "ID", "Name");

    if (elf_dynsym)
    {
        for (i = 0; i < dynsym_num; i++)
        {
            if (is_32_bit_binary())
                type = ELF32_ST_TYPE(elf_dynsym[i].st_info);
            else if (is_64_bit_binary())
                type = ELF64_ST_TYPE(elf_dynsym[i].st_info);
            
            if (type == STT_FUNC)
            {
                if (elf_dynsym[i].st_name != 0 && elf_dynsym[i].st_value == 0)
                {
                    if (&DynSymbolStringTable[elf_dynsym[i].st_name])
                        printf(" %4d: %s\n", j++, &DynSymbolStringTable[elf_dynsym[i].st_name]);
                }
            }
        }
    }

    if (elf_symtab)
    {
        for (i = 0; i < symtab_num; i++)
        {
            if (is_32_bit_binary())
                type = ELF32_ST_TYPE(elf_symtab[i].st_info);
            else if (is_64_bit_binary())
                type = ELF64_ST_TYPE(elf_symtab[i].st_info);
            
            if (type == STT_FUNC && elf_symtab[i].st_value == 0)
            {
                if (elf_symtab[i].st_name != 0)
                {
                    if (&SymbolStringTable[elf_symtab[i].st_name])
                        printf(" %4d: %s\n", j++, &SymbolStringTable[elf_symtab[i].st_name]);
                }
            }
        }
    }
    return;
}

void
print_exported_libraries()
{
    int i, j = 0;

    printf("Elf binary exported libraries:\n");

    printf("   %s: %s\n",
           "ID", "Name");
    
    for (i = 0; i < dynamic_headers; i++)
    {
        if (elf_dyn[i].d_tag == DT_SONAME)
        {
            printf(" %4d: %s\n", j++, &DynSymbolStringTable[elf_dyn[i].d_un.d_val]);
        }
    }
}

void
print_exported_functions()
{
        int i, j = 0;
    uint64_t type;

    printf("Elf exported functions:\n");

    printf("   %s: %s\n",
           "ID", "Name");

    if (elf_dynsym)
    {
        for (i = 0; i < dynsym_num; i++)
        {
            if (is_32_bit_binary())
                type = ELF32_ST_TYPE(elf_dynsym[i].st_info);
            else if (is_64_bit_binary())
                type = ELF64_ST_TYPE(elf_dynsym[i].st_info);
            
            if (type == STT_FUNC)
            {
                if (elf_dynsym[i].st_name != 0 && elf_dynsym[i].st_value != 0)
                {
                    if (&DynSymbolStringTable[elf_dynsym[i].st_name])
                        printf(" %4d: %s\n", j++, &DynSymbolStringTable[elf_dynsym[i].st_name]);
                }
            }
        }
    }

    if (elf_symtab)
    {
        for (i = 0; i < symtab_num; i++)
        {
            if (is_32_bit_binary())
                type = ELF32_ST_TYPE(elf_symtab[i].st_info);
            else if (is_64_bit_binary())
                type = ELF64_ST_TYPE(elf_symtab[i].st_info);
            
            if (type == STT_FUNC && elf_symtab[i].st_value != 0)
            {
                if (elf_symtab[i].st_name != 0)
                {
                    if (&SymbolStringTable[elf_symtab[i].st_name])
                        printf(" %4d: %s\n", j++, &SymbolStringTable[elf_symtab[i].st_name]);
                }
            }
        }
    }
    return;
}

void close_everything()
{
    size_t i;

    if (elf_ehdr && elf_ehdr != (Elf_Ehdr *)-1)
        free_memory(elf_ehdr);

    if (elf_phdr && elf_phdr != (Elf_Phdr *)-1)
        free_memory(elf_phdr);

    if (elf_shdr && elf_shdr != (Elf_Shdr *)-1)
        free_memory(elf_shdr);

    if (elf_dynsym && elf_dynsym != (Elf_Sym *)-1)
        free_memory(elf_dynsym);

    if (elf_symtab && elf_symtab != (Elf_Sym *)-1)
        free_memory(elf_symtab);

    if (elf_rel && elf_rel != (Elf_Rel **)-1)
    {
        for (i = 0; i < rel_sections; i++)
        {
            free_memory(elf_rel[i]);
        }
        free_memory(elf_rel);
    }

    if (elf_rela && elf_rela != (Elf_Rela **)-1)
    {
        for (i = 0; i < rela_sections; i++)
        {
            free_memory(elf_rela[i]);
        }
        free_memory(elf_rela);
    }

    if (elf_dyn && elf_dyn != (Elf_Dyn *)-1)
    {
        free_memory(elf_dyn);
    }

    if (buf_ptr && buf_ptr != (uint8_t *)-1)
        munmap_memory(buf_ptr, buf_ptr_size);
}