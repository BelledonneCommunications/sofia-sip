#
# Makefile.am for sofia features module
#

# ----------------------------------------------------------------------
# Header paths

INCLUDES =		$(INTERNAL_INCLUDES)

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
