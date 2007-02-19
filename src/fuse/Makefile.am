bin_PROGRAMS = cryptofs

cryptofs_SOURCES = \
	cryptofs.c

cryptofs_CFLAGS = \
	-DFUSE_USE_VERSION=26 \
	-I$(top_srcdir)/src/cryptofs \
	$(GLIB_CFLAGS) \
	$(FUSE_CFLAGS)

cryptofs_LDADD = \
	libfs.la \
	$(GLIB_LIBS) \
	$(FUSE_LIBS)

noinst_LTLIBRARIES = libfs.la

libfs_la_SOURCES = \
	fs.c fs.h

libfs_la_CFLAGS = \
	-DFUSE_USE_VERSION=26 \
	-I$(top_srcdir)/src/cryptofs \
	$(GLIB_CFLAGS) \
	$(FUSE_CFLAGS)

libfs_la_LIBADD = \
	$(top_builddir)/src/cryptofs/libcryptofs.la
	$(GLIB_LIBS) \
	$(FUSE_LIBS)
