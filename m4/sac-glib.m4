dnl ======================================================================
dnl SOSXXX: remove, replaced with PKG_CONFIG_...
dnl glib
dnl ======================================================================

AC_DEFUN([AC_WITH_GLIB],[
AC_ARG_WITH(glib,
[  --with-glib=version     use GLib (default=2.0)], [
case "$with_glib" in 
yes | "" ) with_glib=2.0 ;;
esac
], [with_glib=2.0])
])

AC_DEFUN([AC_LIB_GLIB], [
dnl AC_LIB_GLIB(OPTIONAL, ACTION-IF-FOUND, ACTION-IF-NOT-FOUND)
dnl Note - remember to use GLIB_CFLAGS and GLIB_LIBS

AC_REQUIRE([AC_WITH_GLIB])
AC_REQUIRE([AM_HAVE_GLIB])

SAC_ASSERT_DEF([glib])

if test X$with_glib != Xno ; then 
  PKG_CHECK_MODULES([GLIB], glib-$with_glib, [
    AC_DEFINE([HAVE_GLIB], 1, [Define this as 1 if you have glib library])
    HAVE_GLIB=1
    ifelse([$2],,,[$2])dnl
  ], [ifelse([$3],,:,[$3])]) dnl PKG_CHECK_MODULES
fi

if test -z "$1" -a -z "$HAVE_GLIB" ; then
   AC_MSG_ERROR([Gnome GLib (glib-$with_glib) was not found])
fi
]) dnl AC_DEFUN AC_LIB_GLIB

AC_DEFUN([AM_HAVE_GLIB],[
AM_CONDITIONAL([HAVE_GLIB], [test "x$HAVE_GLIB" != x])
])
