lib_LTLIBRARIES = liblufs-cryptofs.la

liblufs_cryptofs_la_SOURCES = \
	cryptofs.c \
	fs.h proto.h

liblufs_cryptofs_la_CFLAGS = \
	-I$(top_srcdir)/src/cryptofs \
	$(GLIB_CFLAGS)

liblufs_cryptofs_la_LDFLAGS = \
	-version-info 0:6:0 -no-undefined

liblufs_cryptofs_la_LIBADD = \
	../cryptofs/libcryptofs.la \
	$(GLIB_LIBS)
