TESTS = \
    open mknod

check_PROGRAMS = $(TESTS)

AM_CFLAGS = \
	-DFUSE_USE_VERSION=25 \
	-I$(top_srcdir)/src/cryptofs \
	-I$(top_srcdir)/src/fuse \
	-I$(top_srcdir)/tests \
	$(GLIB_CFLAGS) \
	$(FUSE_CFLAGS)

LDADD = \
	$(top_builddir)/src/fuse/libfs.la \
	$(top_builddir)/tests/libtest.la
