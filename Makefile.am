AUTOMAKE_OPTIONS = foreign

SUBDIRS = libsofia-sip-ua utils

PACKAGE = @PACKAGE@
VERSION = @VERSION@

EXTRA_DIST = COPYING sofia-sip.spec sofia-sip.spec.in sofia-sip-ua.pc.in

ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = sofia-sip-ua.pc

doxygen:
	@$(MAKE) $(AM_MAKEFLAGS) -C libsofia-sip-ua doxygen
