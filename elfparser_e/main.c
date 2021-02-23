#include "elf_parser.h"
#include <unistd.h>

int
main(int argc, char *argv[])
{
    int c;

    if (argc < 2)
    {
        printf("usage: elfparser [-a/-h/-l/-S/-s/-r] <elf_file>\n");
        printf("\t-a: all the flags\n");
        printf("\t-h: print elf header\n");
        printf("\t-l: print program header\n");
        printf("\t-S: print section header\n");
        printf("\t-s: print symbols header\n");
        printf("\t-r: print reloc headers\n");
        printf("Badly written by: Fare9\n");
        printf("\n\n");
        exit(0);
    }

    if (parse_elf(argv[argc-1]) < 0)
        exit(-1);

    while ((c = getopt(argc, argv, "ahlSsr:")) != -1)
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
        default:
            break;
        }
    }

    // free memory
    close_everything();
}