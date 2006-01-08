#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>
#define GETPW_C
#include "getpw.h"

int	readpwd(char *buf, int bufsiz)
{
        struct  termios old, new;
	int	i;
	char	*p;

	/* get old term settings */
        tcgetattr(0, &old);
        new = old;
        new.c_lflag &= ~(ECHO);
        tcsetattr(0, TCSAFLUSH, &new);
	buf[0] = 0;
	i = read(0, buf, bufsiz-1);
	if (i >= 0)
		buf[i] = 0;
	if ((p = strchr(buf, '\n')))
		*p = 0;
        tcsetattr(0, TCSAFLUSH, &old);
	putchar('\n');
	fflush(stdout);
	return strlen(buf);
}

void	putpwd(char *p)
{
	if (p) {
		memset(p, 'A', MAXPASSLEN);
		munlock(p, MAXPASSLEN);
		free(p);
	}
}

char	*getpwd(char *msg)
{
	char	*p = malloc(MAXPASSLEN);

	printf("%s", msg); fflush(stdout);
	mlock(p, MAXPASSLEN);
	if (!readpwd(p, MAXPASSLEN)) {
		putpwd(p);
		return NULL;
	}
	return p;
}


void	*salloc(int count)
{
	int *p = malloc(count + sizeof(int));
	*p = count;
	if (!p) {
		printf("Out of memory!\n");
		exit(1);
	}
	memset(p+1, 0, count);
	mlock(p+1, count);
	return p+1;
}

void	sfree(void *p)
{
	int	*q = (int *) p - 1;
	memset(p, 0, *q);
	munlock(p, *q);
	free(q);
}
