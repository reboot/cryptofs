TESTS = context name

check_LTLIBRARIES = libtest.la

check_PROGRAMS = context name

AM_CFLAGS = \
	-I$(top_srcdir)/src/cryptofs \
	$(GLIB_CFLAGS)

LDADD = \
	libtest.la
	$(top_builddir)/src/cryptofs/libcryptofs.la

libtest_la_SOURCES = \
	libtest.c libtest.h

libtest_la_LIBADD = \
	$(top_builddir)/src/cryptofs/libcryptofs.la


