#!/usr/bin/python3
# -*- coding: utf-8 -*-

##################################################
# elf_parser python binding
# File: elf.py
##################################################

import sys
import os
from ctypes import *
from enum import Enum

ELF_LIB_NAME = os.path.dirname(__file__) + "/elf_parser.so"


if not os.path.isfile(ELF_LIB_NAME):
    raise FileNotFoundError("%s doesn't exist, did you compile elfparser_e project with make?" % ELF_LIB_NAME)

ELF_LIB = CDLL(ELF_LIB_NAME)


class Elf_Ehdr():

    def __init__(self, e_ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx):
        self.e_ident = e_ident
        self.e_type = e_type
        self.e_machine = e_machine
        self.e_version = e_version
        self.e_entry = e_entry
        self.e_phoff = e_phoff
        self.e_shoff = e_shoff
        self.e_flags = e_flags
        self.e_ehsize = e_ehsize
        self.e_phentsize = e_phentsize
        self.e_phnum = e_phnum
        self.e_shentsize = e_shentsize
        self.e_shnum = e_shnum
        self.e_shstrndx = e_shstrndx


class Elf_Phdr():

    def __init__(self, p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align):
        self.p_type = p_type
        self.p_flags = p_flags
        self.p_offset = p_offset
        self.p_vaddr = p_vaddr
        self.p_paddr = p_paddr
        self.p_filesz = p_filesz
        self.p_memsz = p_memsz
        self.p_align = p_align


class Elf_Shdr():

    def __init__(self, sh_name_offset, sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize):
        self.sh_name_offset = sh_name_offset
        self.sh_name = sh_name
        self.sh_type = sh_type
        self.sh_flags = sh_flags
        self.sh_addr = sh_addr
        self.sh_offset = sh_offset
        self.sh_size = sh_size
        self.sh_link = sh_link
        self.sh_info = sh_info
        self.sh_addralign = sh_addralign
        self.sh_entsize = sh_entsize


class Elf_Sym():

    def __init__(self, st_name_offset, st_name, st_info, st_other, st_shndx, st_value, st_size):
        self.st_name_offset = st_name_offset
        self.st_name = st_name
        self.st_info = st_info
        self.st_other = st_other
        self.st_shndx = st_shndx
        self.st_value = st_value
        self.st_size = st_size


class Elf_Rel():

    def __init__(self, r_offset, r_info):
        self.r_offset = r_offset
        self.r_info = r_info


class Elf_Rela():

    def __init__(self, r_offset, r_info, r_addend):
        self.r_offset = r_offset
        self.r_info = r_info
        self.r_addend = r_addend


class Elf():

    # OS ABI CONSTANTS
    class OSABI():
        ELFOSABI_SYSV           = 0       
        ELFOSABI_HPUX           = 1       
        ELFOSABI_NETBSD         = 2       
        ELFOSABI_GNU            = 3       
        ELFOSABI_LINUX          = ELFOSABI_GNU 
        ELFOSABI_SOLARIS        = 6       
        ELFOSABI_AIX            = 7       
        ELFOSABI_IRIX           = 8       
        ELFOSABI_FREEBSD        = 9       
        ELFOSABI_TRU64          = 10      
        ELFOSABI_MODESTO        = 11      
        ELFOSABI_OPENBSD        = 12      
        ELFOSABI_ARM_AEABI      = 64      
        ELFOSABI_ARM            = 97      
        ELFOSABI_STANDALONE     = 255     

    # Machine
    class Machine():
        EM_NONE         =  0      
        EM_M32          =  1      
        EM_SPARC        =  2      
        EM_386          =  3      
        EM_68K          =  4      
        EM_88K          =  5      
        EM_IAMCU        =  6      
        EM_860          =  7      
        EM_MIPS         =  8      
        EM_S370         =  9      
        EM_MIPS_RS3_LE  = 10                                   
        EM_PARISC       = 15                            
        EM_VPP500       = 17      
        EM_SPARC32PLUS  = 18      
        EM_960          = 19      
        EM_PPC          = 20      
        EM_PPC64        = 21      
        EM_S390         = 22      
        EM_SPU          = 23                                     
        EM_V800         = 36      
        EM_FR20         = 37      
        EM_RH32         = 38      
        EM_RCE          = 39      
        EM_ARM          = 40      
        EM_FAKE_ALPHA   = 41      
        EM_SH           = 42      
        EM_SPARCV9      = 43      
        EM_TRICORE      = 44      
        EM_ARC          = 45      
        EM_H8_300       = 46      
        EM_H8_300H      = 47      
        EM_H8S          = 48      
        EM_H8_500       = 49      
        EM_IA_64        = 50      
        EM_MIPS_X       = 51      
        EM_COLDFIRE     = 52      
        EM_68HC12       = 53      
        EM_MMA          = 54      
        EM_PCP          = 55      
        EM_NCPU         = 56      
        EM_NDR1         = 57      
        EM_STARCORE     = 58      
        EM_ME16         = 59      
        EM_ST100        = 60      
        EM_TINYJ        = 61      
        EM_X86_64       = 62      
        EM_PDSP         = 63      
        EM_PDP10        = 64      
        EM_PDP11        = 65      
        EM_FX66         = 66      
        EM_ST9PLUS      = 67      
        EM_ST7          = 68      
        EM_68HC16       = 69      
        EM_68HC11       = 70      
        EM_68HC08       = 71      
        EM_68HC05       = 72      
        EM_SVX          = 73      
        EM_ST19         = 74      
        EM_VAX          = 75      
        EM_CRIS         = 76      
        EM_JAVELIN      = 77      
        EM_FIREPATH     = 78      
        EM_ZSP          = 79      
        EM_MMIX         = 80      
        EM_HUANY        = 81      
        EM_PRISM        = 82      
        EM_AVR          = 83      
        EM_FR30         = 84      
        EM_D10V         = 85      
        EM_D30V         = 86      
        EM_V850         = 87      
        EM_M32R         = 88      
        EM_MN10300      = 89      
        EM_MN10200      = 90      
        EM_PJ           = 91      
        EM_OPENRISC     = 92      
        EM_ARC_COMPACT  = 93      
        EM_XTENSA       = 94      
        EM_VIDEOCORE    = 95      
        EM_TMM_GPP      = 96      
        EM_NS32K        = 97      
        EM_TPC          = 98      
        EM_SNP1K        = 99      
        EM_ST200        = 100     
        EM_IP2K         = 101     
        EM_MAX          = 102     
        EM_CR           = 103     
        EM_F2MC16       = 104     
        EM_MSP430       = 105     
        EM_BLACKFIN     = 106     
        EM_SE_C33       = 107     
        EM_SEP          = 108     
        EM_ARCA         = 109     
        EM_UNICORE      = 110     
        EM_EXCESS       = 111     
        EM_DXP          = 112     
        EM_ALTERA_NIOS2 = 113     
        EM_CRX          = 114     
        EM_XGATE        = 115     
        EM_C166         = 116     
        EM_M16C         = 117     
        EM_DSPIC30F     = 118     
        EM_CE           = 119     
        EM_M32C         = 120                                  
        EM_TSK3000      = 131     
        EM_RS08         = 132     
        EM_SHARC        = 133     
        EM_ECOG2        = 134     
        EM_SCORE7       = 135     
        EM_DSP24        = 136     
        EM_VIDEOCORE3   = 137     
        EM_LATTICEMICO32= 138    
        EM_SE_C17       = 139     
        EM_TI_C6000     = 140     
        EM_TI_C2000     = 141     
        EM_TI_C5500     = 142     
        EM_TI_ARP32     = 143     
        EM_TI_PRU       = 144                               
        EM_MMDSP_PLUS   = 160     
        EM_CYPRESS_M8C  = 161     
        EM_R32C         = 162     
        EM_TRIMEDIA     = 163     
        EM_QDSP6        = 164     
        EM_8051         = 165     
        EM_STXP7X       = 166     
        EM_NDS32        = 167     
        EM_ECOG1X       = 168     
        EM_MAXQ30       = 169     
        EM_XIMO16       = 170     
        EM_MANIK        = 171     
        EM_CRAYNV2      = 172     
        EM_RX           = 173     
        EM_METAG        = 174     
        EM_MCST_ELBRUS  = 175     
        EM_ECOG16       = 176     
        EM_CR16         = 177     
        EM_ETPU         = 178     
        EM_SLE9X        = 179     
        EM_L10M         = 180     
        EM_K10M         = 181                             
        EM_AARCH64      = 183                             
        EM_AVR32        = 185     
        EM_STM8         = 186     
        EM_TILE64       = 187     
        EM_TILEPRO      = 188     
        EM_MICROBLAZE   = 189     
        EM_CUDA         = 190     
        EM_TILEGX       = 191     
        EM_CLOUDSHIELD  = 192     
        EM_COREA_1ST    = 193     
        EM_COREA_2ND    = 194     
        EM_ARC_COMPACT2 = 195     
        EM_OPEN8        = 196     
        EM_RL78         = 197     
        EM_VIDEOCORE5   = 198     
        EM_78KOR        = 199     
        EM_56800EX      = 200     
        EM_BA1          = 201     
        EM_BA2          = 202     
        EM_XCORE        = 203     
        EM_MCHP_PIC     = 204                           
        EM_KM32         = 210     
        EM_KMX32        = 211     
        EM_EMX16        = 212     
        EM_EMX8         = 213     
        EM_KVARC        = 214     
        EM_CDP          = 215     
        EM_COGE         = 216     
        EM_COOL         = 217     
        EM_NORC         = 218     
        EM_CSR_KALIMBA  = 219     
        EM_Z80          = 220     
        EM_VISIUM       = 221     
        EM_FT32         = 222     
        EM_MOXIE        = 223     
        EM_AMDGPU       = 224                        
        EM_RISCV        = 243     
        EM_BPF          = 247     
        EM_NUM          = 248
        EM_ARC_A5       = EM_ARC_COMPACT
        EM_ALPHA        = 0x9026

    class PhdrType():
        PT_NULL         = 0       
        PT_LOAD         = 1       
        PT_DYNAMIC      = 2       
        PT_INTERP       = 3       
        PT_NOTE         = 4       
        PT_SHLIB        = 5       
        PT_PHDR         = 6       
        PT_TLS          = 7       
        PT_NUM          = 8       
        PT_LOOS         = 0x60000000  
        PT_GNU_EH_FRAME = 0x6474e550  
        PT_GNU_STACK    = 0x6474e551  
        PT_GNU_RELRO    = 0x6474e552  
        PT_LOSUNW       = 0x6ffffffa
        PT_SUNWBSS      = 0x6ffffffa  
        PT_SUNWSTACK    = 0x6ffffffb  
        PT_HISUNW       = 0x6fffffff
        PT_HIOS         = 0x6fffffff  
        PT_LOPROC       = 0x70000000  
        PT_HIPROC       = 0x7fffffff  

    class ShdrType():
        SHT_NULL           =  0     
        SHT_PROGBITS       =  1     
        SHT_SYMTAB         =  2     
        SHT_STRTAB         =  3     
        SHT_RELA           =  4     
        SHT_HASH           =  5     
        SHT_DYNAMIC        =  6     
        SHT_NOTE           =  7     
        SHT_NOBITS         =  8     
        SHT_REL            =  9     
        SHT_SHLIB          =  10        
        SHT_DYNSYM         =  11        
        SHT_INIT_ARRAY     =  14        
        SHT_FINI_ARRAY     =  15        
        SHT_PREINIT_ARRAY  =  16        
        SHT_GROUP          =  17        
        SHT_SYMTAB_SHNDX   =  18        
        SHT_NUM            =  19        
        SHT_LOOS           =  0x60000000    
        SHT_GNU_ATTRIBUTES =  0x6ffffff5   
        SHT_GNU_HASH       =  0x6ffffff6    
        SHT_GNU_LIBLIST    =  0x6ffffff7    
        SHT_CHECKSUM       =  0x6ffffff8    
        SHT_LOSUNW         =  0x6ffffffa    
        SHT_SUNW_move      =  0x6ffffffa
        SHT_SUNW_COMDAT    =  0x6ffffffb
        SHT_SUNW_syminfo   =  0x6ffffffc
        SHT_GNU_verdef     =  0x6ffffffd    
        SHT_GNU_verneed    =  0x6ffffffe    
        SHT_GNU_versym     =  0x6fffffff    
        SHT_HISUNW         =  0x6fffffff    
        SHT_HIOS           =  0x6fffffff    
        SHT_LOPROC         =  0x70000000    
        SHT_HIPROC         =  0x7fffffff    
        SHT_LOUSER         =  0x80000000    
        SHT_HIUSER         =  0x8fffffff 

    class ShdrFlag():
        SHF_WRITE            = (1 << 0)   
        SHF_ALLOC            = (1 << 1)   
        SHF_EXECINSTR        = (1 << 2)   
        SHF_MERGE            = (1 << 4)   
        SHF_STRINGS          = (1 << 5)   
        SHF_INFO_LINK        = (1 << 6)   
        SHF_LINK_ORDER       = (1 << 7)   
        SHF_OS_NONCONFORMING = (1 << 8)   
        SHF_GROUP            = (1 << 9)   
        SHF_TLS              = (1 << 10)  
        SHF_COMPRESSED       = (1 << 11)  
        SHF_MASKOS           = 0x0ff00000 
        SHF_MASKPROC         = 0xf0000000 
        SHF_ORDERED          = (1 << 30)  
        SHF_EXCLUDE          = (1 << 31) 

    class SymVisibility():
        STV_DEFAULT = 0
        STV_INTERNAL = 1
        STV_HIDDEN = 2
        STV_PROTECTED = 3
    
    class SymSection():
        SHN_ABS = 0xfff1
        SHN_UNDEF = 0
        SHN_BEFORE = 0xff00
        SHN_AFTER = 0xff01

    def __init__(self, path_to_elf):
        self.is_elf_ = False
        self.analyzed = False
        self.is_32_bit_ = False
        self.is_64_bit_ = False

        self.elf_ehdr = None
        self.elf_phdr = []
        self.elf_shdr = []
        self.elf_sym = []
        self.elf_rel = []
        self.elf_rela = []

        self.path_to_elf = path_to_elf

        self.__parse()

    def __del__(self):
        if self.analyzed:
            ELF_LIB.close_everything()

    def __parse(self):
        rel_index = 0
        rela_index = 0

        if not os.path.isfile(self.path_to_elf):
            return

        if ELF_LIB.parse_elf(self.path_to_elf.encode()) == -1:
            return

        self.analyzed = True

        e_ident = []
        for i in range(16):
            e_ident.append(ELF_LIB.e_ident(i))

        self.elf_ehdr = Elf_Ehdr(
            e_ident,
            ELF_LIB.e_type(),
            ELF_LIB.e_machine(),
            ELF_LIB.e_version(),
            ELF_LIB.e_entry(),
            ELF_LIB.e_phoff(),
            ELF_LIB.e_shoff(),
            ELF_LIB.e_flags(),
            ELF_LIB.e_ehsize(),
            ELF_LIB.e_phentsize(),
            ELF_LIB.e_phnum(),
            ELF_LIB.e_shentsize(),
            ELF_LIB.e_shnum(),
            ELF_LIB.e_shstrndx()
        )

        if ELF_LIB.is_32_bit_binary() == 1:
            self.is_32_bit_ = True
        elif ELF_LIB.is_64_bit_binary() == 1:
            self.is_64_bit_ = True

        for i in range(self.elf_ehdr.e_phnum):
            self.elf_phdr.append(
                Elf_Phdr(
                    ELF_LIB.p_type(i),
                    ELF_LIB.p_flags(i),
                    ELF_LIB.p_offset(i),
                    ELF_LIB.p_vaddr(i),
                    ELF_LIB.p_paddr(i),
                    ELF_LIB.p_filesz(i),
                    ELF_LIB.p_memsz(i),
                    ELF_LIB.p_align(i)
                )
            )

        ELF_LIB.sh_name_s.restype = c_char_p

        for i in range(self.elf_ehdr.e_shnum):
            self.elf_shdr.append(
                Elf_Shdr(
                    ELF_LIB.sh_name(i),
                    ELF_LIB.sh_name_s(i).decode(),
                    ELF_LIB.sh_type(i),
                    ELF_LIB.sh_flags(i),
                    ELF_LIB.sh_addr(i),
                    ELF_LIB.sh_offset(i),
                    ELF_LIB.sh_size(i),
                    ELF_LIB.sh_link(i),
                    ELF_LIB.sh_info(i),
                    ELF_LIB.sh_addralign(i),
                    ELF_LIB.sh_entsize(i)
                )
            )

        ELF_LIB.dynamic_st_name_s.restype = c_char_p
        ELF_LIB.symtab_st_name_s.restype = c_char_p

        for i in range(ELF_LIB.dynamic_sym_length()):
            self.elf_sym.append(
                Elf_Sym(
                    ELF_LIB.dynamic_st_name(i),
                    ELF_LIB.dynamic_st_name_s(i).decode(),
                    ELF_LIB.dynamic_st_info(i),
                    ELF_LIB.dynamic_st_other(i),
                    ELF_LIB.dynamic_st_shndx(i),
                    ELF_LIB.dynamic_st_value(i),
                    ELF_LIB.dynamic_st_size(i)
                )
            )

        for i in range(ELF_LIB.symtab_sym_length()):
            self.elf_sym.append(
                Elf_Sym(
                    ELF_LIB.symtab_st_name(i),
                    ELF_LIB.symtab_st_name_s(i).decode(),
                    ELF_LIB.symtab_st_info(i),
                    ELF_LIB.symtab_st_other(i),
                    ELF_LIB.symtab_st_shndx(i),
                    ELF_LIB.symtab_st_value(i),
                    ELF_LIB.symtab_st_size(i)
                )
            )
        
        for i in range(self.elf_ehdr.e_shnum):

            if self.elf_shdr[i].sh_type == Elf.ShdrType.SHT_REL:
                n_of_rels = 0
                relocs = []
                if self.is_32_bit:
                    n_of_rels = int(self.elf_shdr[i].sh_size / ELF_LIB.rel_32_size())
                elif self.is_64_bit:
                    n_of_rels = int(self.elf_shdr[i].sh_size / ELF_LIB.rel_64_size())
                
                for j in range(n_of_rels):
                    relocs.append(
                        Elf_Rel(ELF_LIB.rel_r_offset(rel_index,j),
                                ELF_LIB.rel_r_info(rel_index,j))
                    )
                rel_index += 1

                if len(relocs) > 0:
                    self.elf_rel.append(relocs)
            
            if self.elf_shdr[i].sh_type == Elf.ShdrType.SHT_RELA:
                n_of_relas = 0
                relocs = []
                if self.is_32_bit:
                    n_of_relas = int(self.elf_shdr[i].sh_size / ELF_LIB.rela_32_size())
                elif self.is_64_bit:
                    n_of_relas = int(self.elf_shdr[i].sh_size / ELF_LIB.rela_64_size())
                
                for j in range(n_of_relas):
                    relocs.append(
                        Elf_Rela(ELF_LIB.rela_r_offset(rela_index,j),
                                ELF_LIB.rela_r_info(rela_index,j),
                                ELF_LIB.rela_r_addend(rela_index, j))
                    )
                rela_index += 1

                if len(relocs) > 0:
                    self.elf_rela.append(relocs)

        if not self.is_32_bit_ and not self.is_64_bit_:
            return

        self.is_elf_ = True

    def is_elf(self):
        return self.is_elf_

    def is_32_bit(self):
        return self.is_32_bit_

    def is_64_bit(self):
        return self.is_64_bit_

    def print_elf_header(self):
        ELF_LIB.print_elf_ehdr()

    def print_elf_program_header(self):
        ELF_LIB.print_elf_phdr()

    def print_elf_section_header(self):
        ELF_LIB.print_elf_shdr()

    def print_elf_symbols_header(self):
        ELF_LIB.print_elf_sym()

    def print_elf_relocs_header(self):
        ELF_LIB.print_elf_rel_a()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("USAGE: %s <elf_binary>" % sys.argv[0])
        sys.exit(0)

    elf = Elf(sys.argv[1])
    print("Is elf? ",elf.is_elf())

    if not elf.is_elf():
        sys.exit(-1)

    elf.print_elf_header()
    elf.print_elf_program_header()
    elf.print_elf_section_header()
    print(elf.elf_shdr[1].sh_name)
    elf.print_elf_symbols_header()
    elf.print_elf_relocs_header()

    print("Number of rel: %d" % len(elf.elf_rel))

    for i in range(len(elf.elf_rel)):
        print("\tInternal rel: %d" % len(elf.elf_rel[i]))

    print("Number of rela: %d" % len(elf.elf_rela))

    for i in range(len(elf.elf_rela)):
        print("\tInternal rela: %d" % len(elf.elf_rela[i]))