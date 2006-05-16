#
# Makefile.am for sofia-sip/libsofia-sip-ua-glib
#
# Copyright (C) 2006 Nokia Corporation
# Contact: Pekka Pessi <pekka.pessi@nokia.com>
# Licensed under LGPL. See file COPYING.
#

AUTOMAKE_OPTIONS = foreign

SUBDIRS=su-glib nua-glib

GLIB_TARGETS=su-glib/libsu-glib.la

if HAVE_GOBJECT
GOBJECT_TARGETS=nua-glib/libnua-glib.la
endif

lib_LTLIBRARIES = libsofia-sip-ua-glib.la

libsofia_sip_ua_glib_la_SOURCES = 
libsofia_sip_ua_glib_la_LIBADD = $(GLIB_TARGETS) $(GOBJECT_TARGETS)

DOXYGEN = doxygen

EXTRA_DIST = docs/Doxyfile.aliases \
	     docs/Doxyfile.conf \
	     docs/Doxyfile.version

built-sources-recursive clean-built-sources-recursive:
	target=`echo $@ | sed s/-recursive//`; \
	list='$(SUBDIRS)'; for subdir in $$list; do \
	  echo "Making $@ in $$subdir"; \
	  (cd $$subdir && $(MAKE) $(AM_MAKEFLAGS) $$target) \
	done;

doxygen: built-sources
	@cd ${srcdir} ;\
	mkdir -p docs docs/html &&\
	for d in $(DIST_SUBDIRS) $(DIST_SUBDIRS); do \
	  test -r $$d/Doxyfile \
	  && pushd $$d > /dev/null \
	  && echo running ${DOXYGEN} in $$d \
          && ${DOXYGEN} \
          && popd > /dev/null ; \
	done
#	cd ${srcdir}/docs/html && ../hide_emails.sh

.PHONY: built-sources built-sources-am doxygen 
