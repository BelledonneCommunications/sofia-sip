#
# Makefile.am for su-glib module
#
# Copyright (C) 2006 Nokia Corporation
# Contact: Pekka Pessi <pekka.pessi@nokia.com>
# Licensed under LGPL. See file COPYING.
#

# ----------------------------------------------------------------------
# Headers

S_BASE=../../libsofia-sip-ua
INCLUDES =		-I$(srcdir)/$(S_BASE)/su -I$(S_BASE)/su \
			$(GLIB_CFLAGS)

# ----------------------------------------------------------------------
# Build targets

noinst_LTLIBRARIES = 	libsu-glib.la

noinst_PROGRAMS = 	su_source_test

# ----------------------------------------------------------------------
# Tests

TESTS = 		su_source_test

# ----------------------------------------------------------------------
# Rules for building the targets

nobase_include_sofia_HEADERS = \
			sofia-sip/su_source.h

libsu_glib_la_SOURCES = su_source.c

libsu_glib_la_DEPENDENCIES = \
			../../libsofia-sip-ua/libsofia-sip-ua.la

LDADD = 		libsu-glib.la \
			../../libsofia-sip-ua/libsofia-sip-ua.la \
			$(GLIB_LIBS)


if NDEBUG
AM_CFLAGS = -DNDEBUG
endif

# ----------------------------------------------------------------------
# Install and distribution rules

# ----------------------------------------------------------------------
# Automake options

AUTOMAKE_OPTIONS = 	foreign

# ----------------------------------------------------------------------
# Sofia specific rules
