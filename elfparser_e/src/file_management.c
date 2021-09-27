#include "file_management.h"
#include <unistd.h>


int
open_file(const char *pathname, int flags)
{
	int fd;

	if (pathname == NULL)
	{
		fprintf(stderr, "open_file: error pathname cannot be NULL\n");
		return (-1);
	}

	if ((fd = open(pathname, flags)) < 0)
	{
		perror("open_file");
		return (-1);
	}

	return (fd);
}

int 
open_file_reading(const char *pathname)
{
	int fd;

	if (pathname == NULL)
	{
		fprintf(stderr, "open_file_reading: error pathname cannot be NULL\n");
		return (-1);
	}

	if ((fd = open(pathname, O_RDONLY)) < 0)
	{
		perror("open_file_reading");
		return (-1);
	}

	return (fd);
}


int 
open_file_writing(const char *pathname)
{
	int fd;

	if (pathname == NULL)
	{
		fprintf(stderr, "open_file_writing: error pathname cannot be NULL\n");
		return (-1);
	}

	if ((fd = open(pathname, O_WRONLY)) < 0)
	{
		perror("open_file_writing");
		return (-1);
	}

	return (fd);
}

int
open_file_read_write(const char *pathname)
{
	int fd;

	if (pathname == NULL)
	{
		fprintf(stderr, "open_file_read_Write: error pathname cannot be NULL\n");
		return (-1);
	}

	if ((fd = open(pathname, O_RDWR)) < 0)
	{
		perror("open_file_read_write");
		return (-1);
	}

	return (fd);
}

ssize_t
get_file_size(int fd)
{
	struct stat buf_stat;

	if (fd < 0)
	{
		fprintf(stderr, "close_file: file descriptor cannot be negative number\n");
		return (INVALID_FILE_DESCRIPTOR);
	}

	if (fstat(fd, &buf_stat) < 0)
	{
		perror("get_file_size");
		return (-1);
	}

	return (buf_stat.st_size);
}

int
close_file(int fd)
{
	if (fd < 0)
	{
		fprintf(stderr, "close_file: file descriptor cannot be negative number\n");
		return (INVALID_FILE_DESCRIPTOR);
	}

	return close(fd);
}