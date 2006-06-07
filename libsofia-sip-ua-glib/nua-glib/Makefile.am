#
# Makefile.am for nua-glib module
#
# Copyright (C) 2006 Nokia Corporation
# Contact: Pekka Pessi <pekka.pessi@nokia.com>
# Licensed under LGPL. See file COPYING.
#

GLIB_BUILT = 	nua_glib_marshal.c \
		nua_glib_marshal.h

# ----------------------------------------------------------------------
# Header paths

S_BASE = $(top_srcdir)/libsofia-sip-ua
B_BASE = $(top_builddir)/libsofia-sip-ua

INCLUDES = 		-I$(S_BASE)/bnf -I$(B_BASE)/bnf \
	 		-I$(S_BASE)/ipt -I$(B_BASE)/ipt \
	 		-I$(S_BASE)/iptsec -I$(B_BASE)/iptsec \
	 		-I$(S_BASE)/http -I$(B_BASE)/http \
			-I$(S_BASE)/msg -I$(B_BASE)/msg \
			-I$(S_BASE)/nea -I$(B_BASE)/nea \
			-I$(S_BASE)/nta -I$(B_BASE)/nta \
			-I$(S_BASE)/nth -I$(B_BASE)/nth \
			-I$(S_BASE)/nua -I$(B_BASE)/nua \
			-I$(S_BASE)/sdp -I$(B_BASE)/sdp \
			-I$(S_BASE)/sip -I$(B_BASE)/sip \
			-I$(S_BASE)/stun -I$(B_BASE)/stun \
			-I$(S_BASE)/soa -I$(B_BASE)/soa \
			-I$(S_BASE)/tport -I$(B_BASE)/tport \
			-I$(S_BASE)/url -I$(B_BASE)/url \
			-I$(S_BASE)/su -I$(B_BASE)/su \
			-I$(srcdir)/../su-glib/ \
			$(GLIB_CFLAGS)

# ----------------------------------------------------------------------
# Build targets

noinst_LTLIBRARIES = 	

if HAVE_GOBJECT
noinst_LTLIBRARIES += 	libnua-glib.la
endif

# ----------------------------------------------------------------------
# Rules for building the targets

BUILT_SOURCES =		$(GLIB_BUILT)

nobase_include_sofia_HEADERS =
if HAVE_GOBJECT
nobase_include_sofia_HEADERS += \
			sofia-sip/nua_glib.h
endif

noinst_HEADERS =	nua_glib_priv.h

check_PROGRAMS =	test_nua_glib

libnua_glib_la_SOURCES = nua_glib.c

libnua_glib_la_LIBADD =  nua_glib_marshal.lo

LDADD =  		$(GLIB_LIBS) -lgobject-2.0 \
			libnua-glib.la ../su-glib/libsu-glib.la \
			../../libsofia-sip-ua/libsofia-sip-ua.la

test_nua_glib_LDFLAGS = -static

%_marshal.h: ${srcdir}/%_marshal.list ${srcdir}/Makefile.am
	glib-genmarshal --header --prefix=$(subst -,_,$*)_marshal $< > $*_marshal.h

%_marshal.c: ${srcdir}/%_marshal.list ${srcdir}/Makefile.am
	glib-genmarshal --body --prefix=$(subst -,_,$*)_marshal $< > $*_marshal.c

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST =		Doxyfile nua_glib.docs $(BUILT_SOURCES)

# ----------------------------------------------------------------------
# Sofia specific rules

include ../../libsofia-sip-ua/sofia.am
