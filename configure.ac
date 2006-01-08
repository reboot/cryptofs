dnl Process this file with autoconf to produce a configure script.
AC_INIT(configure.ac)
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE(cryptofs, 0.4.0)
AM_CONFIG_HEADER(config.h)

AC_PROG_CC
AC_PROG_LIBTOOL

AM_PATH_LIBGCRYPT(1.1.44, 
    :,
    AC_MSG_ERROR([libgcrypt >= 1.1.44 is required to build CryptoFS]))
PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.2.0)

AC_CHECK_PROG(have_pinentry, "pinentry", "yes", "no")
AC_ARG_WITH(pinentry, 
	    [  --with-pinentry         Enable support for pinentry program to enter passwords], 
	    [ with_pinentry=$withval ], 
	    [ with_pinentry=$have_pinentry ])
AM_CONDITIONAL(WITH_PINENTRY, [ test x$with_pinentry = "xyes" ])
if test x$with_pinentry = "xyes"; then
    AC_DEFINE(WITH_PINENTRY, 1, [Enable pinentry support])
fi

AC_OUTPUT([
Makefile
config/Makefile
doc/Makefile
src/Makefile
src/cryptofs/Makefile
src/lufs/Makefile
])
