#include "elf_parser.h"
#include <unistd.h>

int
main(int argc, char *argv[])
{
    int c;

    if (argc < 2)
    {
        printf("usage: elfparser [-a/-h/-l/-S/-s/-r/-L/-i/-e] <elf_file>\n");
        printf("\t-a: all the flags\n");
        printf("\t-h: print elf header\n");
        printf("\t-l: print program header\n");
        printf("\t-S: print section header\n");
        printf("\t-s: print symbols header\n");
        printf("\t-r: print reloc headers\n");
        printf("\t-D: print dynamic program headers\n");
        printf("\t-L: print imported libraries\n");
        printf("\t-i: print imported functions\n");
        printf("\t-e: print exported libraries\n");
        printf("\t-f: print exported functions\n");
        printf("Badly written by: Fare9\n");
        printf("\n\n");
        exit(0);
    }

    if (parse_elf(argv[argc-1]) < 0)
        exit(-1);

    while ((c = getopt(argc, argv, "ahlSsrDLief:")) != -1)
	{
		switch(c)
		{
        case 'a':
            print_elf_ehdr();
            printf("\n");
            print_elf_phdr();
            printf("\n");
            print_elf_shdr();
            printf("\n");
            print_elf_sym();
            printf("\n");
            print_elf_rel_a();
            printf("\n");
            print_elf_dynamic();
            printf("\n");
            print_imported_libraries();
            printf("\n");
            print_imported_functions();
            printf("\n");
            print_exported_libraries();
            printf("\n");
            print_exported_functions();
            printf("\n");
            break;
        case 'h':
            print_elf_ehdr();
            printf("\n");
            break;
        case 'l':
            print_elf_phdr();
            printf("\n");
            break;
        case 'S':
            print_elf_shdr();
            printf("\n");
            break;
        case 's':
            print_elf_sym();
            printf("\n");
            break;
        case 'r':
            print_elf_rel_a();
            printf("\n");
            break;
        case 'D':
            print_elf_dynamic();
            printf("\n");
            break;
        case 'L':
            print_imported_libraries();
            printf("\n");
            break;
        case 'i':
            print_imported_functions();
            printf("\n");
            break;
        case 'e':
            print_exported_libraries();
            printf("\n");
            break;
        case 'f':
            print_exported_functions();
            printf("\n");
            break;
        default:
            break;
        }
    }

    // free memory
    close_everything();
}