# if BUILD_LUFS
# LUFSDIRS = lufs
# else
LUFSDIRS =
# endif

if BUILD_FUSE
FUSEDIRS = fuse
else
FUSEDIRS =
endif

SUBDIRS = . cryptofs $(LUFSDIRS) $(FUSEDIRS)

check_LTLIBRARIES = libtest.la

libtest_la_SOURCES = \
	libtest.c libtest.h

libtest_la_CFLAGS = \
	-D_FILE_OFFSET_BITS=64 \
	-I$(top_srcdir)/src/cryptofs \
	$(GLIB_CFLAGS)

libtest_la_LIBADD = \
	$(top_builddir)/src/cryptofs/libcryptofs.la
