dnl Process this file with autoconf to produce a configure script.
AC_INIT(configure.ac)
AC_CONFIG_AUX_DIR(config)
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE(cryptofs, 0.6.0)
AM_CONFIG_HEADER(config.h)

AC_PROG_CC
AC_PROG_LIBTOOL

AM_PATH_LIBGCRYPT(1.1.44, 
    :,
    AC_MSG_ERROR([libgcrypt >= 1.1.44 is required to build CryptoFS]))
PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.6.0)

case $target_os in
    *bsd* | *darwin*)
	AC_DEFINE(BSD, 1, [Build for BSD])
	enable_lufs=no
	;;
esac

# --- LUFS ---
AC_ARG_ENABLE(lufs, 
	      [  --disable-lufs          don't build CryptoFS for LUFS ], 
	      [ enable_lufs=$enableval ])
AM_CONDITIONAL(BUILD_LUFS, [ test x"$enable_lufs" != x"no" ])

# --- FUSE ---
AC_ARG_ENABLE(fuse, 
	      [  --disable-fuse          don't build CryptoFS for FUSE ], 
	      [ enable_fuse=$enableval ])
if test x"$enable_fuse" != x"no"; then
    PKG_CHECK_MODULES(FUSE, [ fuse ], [], [ enable_fuse="no" ])
fi
AM_CONDITIONAL(BUILD_FUSE, [ test x"$enable_fuse" != x"no" ])

# --- PinEntry ---
AC_ARG_WITH(pinentry, 
	    [  --with-pinentry         Enable support for pinentry program to enter passwords], 
	    [ with_pinentry=$withval ])
if test x"$with_pinentry" != x"no"; then
    AC_CHECK_PROG(have_pinentry, "pinentry", "yes", "no")
    with_pinentry=$have_pinentry
fi
AM_CONDITIONAL(WITH_PINENTRY, [ test x"$with_pinentry" != x"no" ])
if test x"$with_pinentry" != x"no"; then
    AC_DEFINE(WITH_PINENTRY, 1, [Enable pinentry support])
fi

AC_OUTPUT([
Makefile
config/Makefile
doc/Makefile
src/Makefile
src/cryptofs/Makefile
src/lufs/Makefile
src/fuse/Makefile
tests/Makefile
tests/cryptofs/Makefile
tests/fuse/Makefile
])
