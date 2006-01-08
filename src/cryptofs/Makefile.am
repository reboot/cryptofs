noinst_LTLIBRARIES = libcryptofs.la

if WITH_PINENTRY
PASSWORD_SOURCES = pinentry.c pinentry.h
else
PASSWORD_SOURCES = getpw.c getpw.h
endif

libcryptofs_la_SOURCES = \
	base64.c base64.h \
	crypto.c crypto.h \
	utils.c utils.h \
	$(PASSWORD_SOURCES)

libcryptofs_la_CFLAGS = \
	$(LIBGCRYPT_CFLAGS) \
	$(GLIB_CFLAGS)

libcryptofs_la_LDFLAGS = \
	-no-undefined

libcryptofs_la_LIBADD = \
	$(LIBGCRYPT_LIBS) \
	$(GLIB_LIBS)

