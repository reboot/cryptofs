dnl Process this file with autoconf to produce a configure script.
AC_INIT(configure.ac)
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE(cryptofs, 0.3.0)
AM_CONFIG_HEADER(config.h)

AC_PROG_CC
AC_PROG_LIBTOOL

AM_PATH_LIBGCRYPT(1.1.44)
PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.2.0)

AC_OUTPUT([
Makefile
config/Makefile
doc/Makefile
src/Makefile
src/lufs/Makefile
])
