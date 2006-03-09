#
# Makefile.am for nua-glib module
#
# Copyright (C) 2006 Nokia Corporation
# Contact: Pekka Pessi <pekka.pessi@nokia.com>
# Licensed under LGPL. See file COPYING.
#

if HAVE_GLIB
GLIB_BUILT = 	nua_glib_marshal.c \
		nua_glib_marshal.h
else
GLIB_BUILT =
endif

# ----------------------------------------------------------------------
# Header paths

S_BASE=../../libsofia-sip-ua

INCLUDES = 		-I$(srcdir)/$(S_BASE)/bnf -I$(S_BASE)/bnf \
	 		-I$(srcdir)/$(S_BASE)/ipt -I$(S_BASE)/ipt \
	 		-I$(srcdir)/$(S_BASE)/iptsec -I$(S_BASE)/iptsec \
	 		-I$(srcdir)/$(S_BASE)/http -I$(S_BASE)/http \
			-I$(srcdir)/$(S_BASE)/msg -I$(S_BASE)/msg \
			-I$(srcdir)/$(S_BASE)/nea -I$(S_BASE)/nea \
			-I$(srcdir)/$(S_BASE)/nta -I$(S_BASE)/nta \
			-I$(srcdir)/$(S_BASE)/nth -I$(S_BASE)/nth \
			-I$(srcdir)/$(S_BASE)/nua -I$(S_BASE)/nua \
			-I$(srcdir)/$(S_BASE)/sdp -I$(S_BASE)/sdp \
			-I$(srcdir)/$(S_BASE)/sip -I$(S_BASE)/sip \
			-I$(srcdir)/$(S_BASE)/soa -I$(S_BASE)/soa \
			-I$(srcdir)/$(S_BASE)/tport -I$(S_BASE)/tport \
			-I$(srcdir)/$(S_BASE)/url -I$(S_BASE)/url \
			-I$(srcdir)/$(S_BASE)/su -I$(S_BASE)/su \
			$(GLIB_CFLAGS)

# ----------------------------------------------------------------------
# Build targets

noinst_LTLIBRARIES = 	libnua-glib.la

# ----------------------------------------------------------------------
# Rules for building the targets

BUILT_SOURCES =		$(GLIB_BUILT)

nobase_include_sofia_HEADERS = \
			sofia-sip/nua_glib.h

noinst_HEADERS =	nua_glib_priv.h
noinst_PROGRAMS =	test_nua_glib

libnua_glib_la_SOURCES = \
			nua_glib.c \
			$(GLIB_BUILT)

LDADD = 		$(GLIB_LIBS) -lgobject-2.0 \
			libnua-glib.la \
			../../libsofia-sip-ua/libsofia-sip-ua.la

test_nua_glib_LDFLAGS = -static
test_nua_glib_SOURCES = test_nua_glib.c

if HAVE_GLIB
%_marshal.h: %_marshal.list Makefile
	glib-genmarshal --header --prefix=$(subst -,_,$*)_marshal $< > $*_marshal.h

%_marshal.c: %_marshal.list Makefile
	glib-genmarshal --body --prefix=$(subst -,_,$*)_marshal $< > $*_marshal.c
endif

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST =		Doxyfile nua_glib.docs $(BUILT_SOURCES)

# ----------------------------------------------------------------------
# Sofia specific rules

