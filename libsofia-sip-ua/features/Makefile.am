#
# Makefile.am for sofia features module
#

# ----------------------------------------------------------------------
# Header paths

INCLUDES = 		-I$(srcdir)/../bnf \
	 		-I$(srcdir)/../ipt \
	 		-I$(srcdir)/../iptsec \
	 		-I$(srcdir)/../http \
			-I$(srcdir)/../msg \
			-I$(srcdir)/../nea \
			-I$(srcdir)/../nta \
			-I$(srcdir)/../nth \
			-I$(srcdir)/../nua \
			-I$(srcdir)/../sdp \
			-I$(srcdir)/../sip \
			-I$(srcdir)/../soa \
			-I$(srcdir)/../tport \
			-I$(srcdir)/../url \
			-I$(srcdir)/../su

# ----------------------------------------------------------------------
# Build targets

noinst_LTLIBRARIES = 	libfeatures.la

# ----------------------------------------------------------------------
# Rules for building the targets

nobase_include_sofia_HEADERS = sofia-sip/features.h

libfeatures_la_SOURCES = features.c

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST =		Doxyfile features.docs

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am
