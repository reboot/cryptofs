bin_PROGRAMS = cryptofs

cryptofs_SOURCES = cryptofs.c

cryptofs_CFLAGS = \
	-DFUSE_USE_VERSION=25 \
	-I$(top_srcdir)/src/cryptofs \
	$(GLIB_CFLAGS) \
	$(FUSE_CFLAGS)

cryptofs_LDADD = \
	$(top_builddir)/src/cryptofs/libcryptofs.la \
	$(GLIB_LIBS) \
	$(FUSE_LIBS)
