AUTOMAKE_OPTIONS = foreign 1.6.1

SUBDIRS = libsofia-sip-ua utils
DIST_SUBDIRS = $(SUBDIRS) win32

PACKAGE = @PACKAGE@
VERSION = @VERSION@

EXTRA_DIST = AUTHORS COPYING TODO \
   packages/sofia-sip.spec packages/sofia-sip.spec.in packages/sofia-sip-ua.pc.in

ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = packages/sofia-sip-ua.pc

dist_m4_DATA = m4/sac-general.m4 m4/sac-su.m4 m4/sac-su2.m4

doxygen coverage built-sources:
	@$(MAKE) $(AM_MAKEFLAGS) -C libsofia-sip-ua $@
