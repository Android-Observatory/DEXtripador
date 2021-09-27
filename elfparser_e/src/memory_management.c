#include "memory_management.h"


void* 
allocate_memory(size_t size)
{
    void* ret_address;

    if (size == 0)
    {
        fprintf(stderr, "allocate_memory: size cannot be 0\n");
        return ((void*)-1);
    }

    if ((ret_address = malloc(size)) == NULL)
    {
        fprintf(stderr, "allocate_memory: error memory allocation\n");
        return ((void*)-1);
    }

    return (ret_address);
}


void*
realloc_memory(void* ptr, size_t size)
{
    void* ret_address;

    if (size == 0)
    {
        fprintf(stderr, "realloc_memory: size cannot be 0\n");
        return ((void*)-1);
    }

    if (ptr == NULL)
    {
        fprintf(stderr, "realloc_memory: cannot realloc NULL pointer\n");
        return ((void*)-1);
    }

    if ((ret_address = realloc(ptr, size)) == NULL)
    {
        fprintf(stderr, "realloc_memory: error memory allocation\n");
        return ((void*)-1);
    }
    return (ret_address);
}

void*
mmap_file_read(size_t length, int fd)
{
    void* file_memory;

    if (length == 0)
    {
        fprintf(stderr, "mmap_file_read: length cannot be 0\n");
        return ((void*)-1);
    }

    if (fd < 0)
    {
        fprintf(stderr, "mmap_file_read: file descriptor cannot be lower than zero\n");
        return ((void*)-1);
    }

    if ((file_memory = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    {
        perror("mmap_file_read");
        return ((void*)-1);
    }

    return (file_memory);
}

void*
mmap_file_write(size_t length, int fd)
{
    void* file_memory;

    if (length == 0)
    {
        fprintf(stderr, "mmap_file_write: length cannot be 0\n");
        return ((void*)-1);
    }

    if (fd < 0)
    {
        fprintf(stderr, "mmap_file_write: file descriptor cannot be lower than zero\n");
        return ((void*)-1);
    }

    if ((file_memory = mmap(NULL, length, PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    {
        perror("mmap_file_write");
        return ((void*)-1);
    }

    return (file_memory);
}


void*
mmap_file_read_write(size_t length, int fd)
{
    void* file_memory;

    if (length == 0)
    {
        fprintf(stderr, "mmap_file_read_write: length cannot be 0\n");
        return ((void*)-1);
    }

    if (fd < 0)
    {
        fprintf(stderr, "mmap_file_read_write: file descriptor cannot be lower than zero\n");
        return ((void*)-1);
    }

    if ((file_memory = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    {
        perror("mmap_file_read_write");
        return ((void*)-1);
    }

    return (file_memory);
}

int
free_memory(void *ptr)
{
    if (ptr == NULL)
    {
        fprintf(stderr, "free_memory: cannot free NULL pointer\n");
        return (-1);
    }

    free(ptr);

    ptr = NULL;

    return (0);
}

int
munmap_memory(void* ptr, size_t size)
{
    if (size == 0)
    {
        fprintf(stderr, "munmap_memory: size cannot be 0\n");
        return (-1);
    }

    if (ptr == NULL)
    {
        fprintf(stderr, "munmap_memory: cannot munmap NULL pointer\n");
        return (-1);
    }

    if (munmap(ptr, size) < 0)
    {
        perror("munmap_memory");
        return (-1);
    }

    return (0);
}