#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

void usage(const char * prog)
{
	printf(
"%s <fd> <filename>\n"
"Checks that the open file descriptor (referenced by number) has the same\n"
"inode as the filename.\n"
"Returns 0 on match and 1 on non-match\n", prog);
}

int main(int argc, char *argv[])
{
	struct stat fd_statbuf, file_statbuf;
	int ret;
	int fd;

	if (argc < 3) {
		usage(argv[0]);
		return 1;
	}

	fd = strtoul(argv[1], NULL, 0);

	ret = fstat(fd, &fd_statbuf);
	if (ret) {
		perror("fstat");
		return -1;
	}

	ret = stat(argv[2], &file_statbuf);
	if (ret) {
		perror("stat");
		return -1;
	}

	return !(fd_statbuf.st_ino == file_statbuf.st_ino);
}
