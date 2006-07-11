#
# Makefile.am for sofia-sip package
#
# Copyright (C) 2005,2006 Nokia Corporation
# Contact: Pekka Pessi <pekka.pessi@nokia.com>
# Licensed under LGPL. See file COPYING.

AUTOMAKE_OPTIONS = foreign 1.6.1

SUBDIRS = libsofia-sip-ua $(GLIB_SUBDIRS) utils packages
DIST_SUBDIRS = libsofia-sip-ua libsofia-sip-ua-glib utils packages win32

if HAVE_GLIB
GLIB_SUBDIRS = libsofia-sip-ua-glib
endif

PACKAGE = @PACKAGE@
VERSION = @VERSION@

EXTRA_DIST =	AUTHORS COPYING COPYRIGHTS \
		README README.developers RELEASE TODO

ACLOCAL_AMFLAGS = -I m4

dist_m4_DATA = 	m4/sac-general.m4 m4/sac-su.m4
EXTRA_DIST += 	m4/sac-su2.m4 m4/sac-tport.m4 m4/sac-openssl.m4

dist_man_MANS = man/man1/sip-date.1 man/man1/sip-options.1 \
		man/man1/localinfo.1 man/man1/addrinfo.1 \
		man/man1/stunc.1 man/man1/sip-dig.1

manpages $(MANS):
	-mkdir -p $(srcdir)/man $(srcdir)/man/man1 2> /dev/null
	cd $(srcdir)/utils; $(DOXYGEN)
if !HAVE_DOXYGEN
	-touch $(MANS)
endif

coverage built-sources clean-built-sources:
	@$(MAKE) $(AM_MAKEFLAGS) -C libsofia-sip-ua $@

doxygen:
if HAVE_DOXYGEN
	@$(MAKE) $(AM_MAKEFLAGS) -C libsofia-sip-ua $@
endif

.PHONY: coverage built-sources clean-built-sources doxygen
.PHONY: manpages doxygen-manpages
