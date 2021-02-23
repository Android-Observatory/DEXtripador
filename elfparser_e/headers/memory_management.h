#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef MEMORY_MANAGEMENT_H
#define MEMORY_MANAGEMENT_H

void* allocate_memory(size_t size);
void* realloc_memory(void* ptr, size_t size);
void* mmap_file_read(size_t length, int fd);
void* mmap_file_write(size_t length, int fd);
void* mmap_file_read_write(size_t length, int fd);

int free_memory(void *ptr);
int munmap_memory(void* ptr, size_t size);

#endif