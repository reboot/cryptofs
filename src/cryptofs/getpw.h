#ifndef GETPW_H
#define GETPW_H

#define	MAXPASSLEN	512

#ifdef GETPW_C
#define EXTERN extern
#else
#define EXTERN
#endif

EXTERN	int	readpwd(char *buf, int bufsiz);
EXTERN	void	putpwd(char *p);
EXTERN	char	*getpwd(char *);
EXTERN	void	*salloc(int count);
EXTERN	void	sfree(void *p);

#endif
