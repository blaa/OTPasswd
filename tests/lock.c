#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define LOCK_FILE ".otpasswd.lck"
int fd = -1;

int lock()
{
	struct flock fl;

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = fl.l_len = 0;

	fd = open(LOCK_FILE, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR);

	if (fd == -1) {
		/* Unable to create file, therefore unable to obtain lock */
		perror("open");
		printf("Unable to open a state file\n");
		return 1;
	}

	if (fcntl(fd, F_SETLK, &fl) == 0) {
		printf("Locked\n");
		return 0;
	}

	close(fd);
	printf("Unable to lock\n");
	return 1;
}

void overwrite()
{
	FILE *f = fopen(LOCK_FILE, "w");
	if (!f) {
		printf("Unable to open for overwrite\n");
		return;
	}
	fprintf(f, "Dupablada\n");
	if (fflush(f) != 0) {
		printf("Unable to fflush\n");
	}
	fclose(f);
}

int unlock()
{
	struct flock fl;

	if (fd < 0) {
		printf("No lock to release!\n");
		return 1;
	}

	fl.l_type = F_UNLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = fl.l_len = 0;

	int ret = fcntl(fd, F_SETLK, &fl);

	close(fd);
	fd = -1;

	if (ret != 0) {
		printf("Strange error while releasing lock\n");
		/* Strange error while releasing the lock */
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	if (lock() != 0) {
		return 1;
	}

//	overwrite();
	printf("Waiting for keypress\n"); getchar();
	unlock();
	return 0;
}
