AUTOMAKE_OPTIONS = foreign 1.6.1

SUBDIRS = libsofia-sip-ua utils packages
DIST_SUBDIRS = $(SUBDIRS) win32

PACKAGE = @PACKAGE@
VERSION = @VERSION@

EXTRA_DIST =	AUTHORS COPYING COPYRIGHTS \
		README README.developers RELEASE TODO

ACLOCAL_AMFLAGS = -I m4

dist_m4_DATA = 	m4/sac-general.m4 m4/sac-su.m4
EXTRA_DIST += 	m4/sac-su2.m4 m4/sac-tport.m4 m4/sac-openssl.m4

man_MANS = 	man/man1/sip-date.1 man/man1/sip-options.1 \
		man/man1/localinfo.1 man/man1/addrinfo.1 

$(man_MANS): doxygen

coverage built-sources clean-built-sources:
	@$(MAKE) $(AM_MAKEFLAGS) -C libsofia-sip-ua $@

doxygen:
if HAVE_DOXYGEN
	@$(MAKE) $(AM_MAKEFLAGS) -C libsofia-sip-ua $@
	mkdir -p man man/man1 2> /dev/null
	cd utils; doxygen
else
	mkdir -p man man/man1 2> /dev/null
	-touch $(man_DATA)
endif

.PHONY: coverage built-sources clean-built-sources doxygen
