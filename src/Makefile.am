SUBDIRS = lufs

lib_LTLIBRARIES = liblufs-cryptofs.la

liblufs_cryptofs_la_SOURCES = \
	cryptofs.c \
	base64.c base64.h \
	getpw.c getpw.h

liblufs_cryptofs_la_CFLAGS = \
	$(LIBGCRYPT_CFLAGS) \
	$(GLIB_CFLAGS)

liblufs_cryptofs_la_LDFLAGS = \
	-version-info 0:3:0

liblufs_cryptofs_la_LIBADD = \
	$(LIBGCRYPT_LIBS) \
	$(GLIB_LIBS)

