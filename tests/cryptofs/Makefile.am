TESTS = \
    context \
    encdecname conffilename \
    writereadblock \
    write

check_PROGRAMS = $(TESTS)

AM_CFLAGS = \
	-D_FILE_OFFSET_BITS=64 \
	-I$(top_srcdir)/src/cryptofs \
	-I$(top_srcdir)/tests \
	$(GLIB_CFLAGS)

LDADD = \
	$(top_builddir)/tests/libtest.la
