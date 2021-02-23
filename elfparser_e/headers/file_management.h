#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>


#ifndef FILE_MANAGEMENT_H
#define FILE_MANAGEMENT_H

#ifndef INVALID_FILE_DESCRIPTOR
#define INVALID_FILE_DESCRIPTOR -1
#endif

int open_file(const char *pathname, int flags);
int open_file_reading(const char *pathname);
int open_file_writing(const char *pathname);
int open_file_read_write(const char *pathname);

ssize_t get_file_size(int fd);


int close_file(int fd);


#endif

