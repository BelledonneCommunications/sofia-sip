#
# Makefile.am for sofia-sip/libsofia-sip-ua
#
# Copyright (C) 2005,2006 Nokia Corporation
# Contact: Pekka Pessi <pekka.pessi@nokia.com>
# Licensed under LGPL. See file COPYING.
#
# ref: http://www.gnu.org/software/automake/manual/automake.html

AUTOMAKE_OPTIONS = foreign

# note: order does matter in the subdir list
SUBDIRS = su features bnf sresolv sdp url msg sip stun ipt soa \
	  tport http nta nea iptsec nth nua
DIST_SUBDIRS = $(SUBDIRS) docs

EXTRA_DIST = sofia.am
DOXYGEN = doxygen

lib_LTLIBRARIES = libsofia-sip-ua.la

libsofia_sip_ua_la_SOURCES = 
libsofia_sip_ua_la_LIBADD = 	bnf/libbnf.la \
				features/libfeatures.la \
				ipt/libipt.la \
				iptsec/libiptsec.la \
				msg/libmsg.la \
				nea/libnea.la \
				nta/libnta.la \
				nth/libnth.la \
				nua/libnua.la \
				http/libhttp.la \
				sdp/libsdp.la \
				sip/libsip.la \
				soa/libsoa.la \
				sresolv/libsresolv.la \
				su/libsu.la \
				stun/libstun.la \
				tport/libtport.la \
				url/liburl.la
# set the libtool version info version:revision:age for libsofia-sip-ua
# - soname to 'libsofia-sip-ua.so.(CUR-AGE)'
libsofia_sip_ua_la_LDFLAGS = \
	-version-info $(LIBVER_SOFIA_SIP_UA_CUR):$(LIBVER_SOFIA_SIP_UA_REV):$(LIBVER_SOFIA_SIP_UA_AGE)

if ENABLE_COVERAGE
COVERAGE_RECURSIVE = coverage-recursive
coverage: $(COVERAGE_RECURSIVE)
endif

all-recursive: built-sources-recursive
built-sources: built-sources-recursive 
clean-built-sources: clean-built-sources-recursive

built-sources-recursive clean-built-sources-recursive $(COVERAGE_RECURSIVE):
	target=`echo $@ | sed s/-recursive//`; \
	list='$(SUBDIRS)'; for subdir in $$list; do \
	  echo "Making $@ in $$subdir"; \
	  (cd $$subdir && $(MAKE) $(AM_MAKEFLAGS) $$target) \
	done;

empty-doxytags:
	@echo Generating empty doxytags
	cd ${srcdir}; \
	mkdir -p docs/html ; \
	for d in $(DIST_SUBDIRS); do \
	  test -r $$d/Doxyfile || continue ; \
	  if ! test -r docs/doxytags_$$d ; then \
		echo '<?xml version="1.0"?>' > docs/doxytags_$$d ; \
		echo '<tagfile />' >>  docs/doxytags_$$d ; \
          fi ; \
	done

doxygen: built-sources empty-doxytags 
	@cd ${srcdir} ;\
	for d in $(DIST_SUBDIRS) $(DIST_SUBDIRS); do \
	  test -r $$d/Doxyfile \
	  && pushd $$d > /dev/null \
	  && echo running ${DOXYGEN} in $$d \
          && ${DOXYGEN} \
          && popd > /dev/null ; \
	done
	cd ${srcdir}/docs/html && ../hide_emails.sh

.PHONY: built-sources built-sources-am empty-doxytags doxygen 
