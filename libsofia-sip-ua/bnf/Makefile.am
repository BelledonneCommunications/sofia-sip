#
# Makefile.am for bnf module
#

# ----------------------------------------------------------------------
# Header paths

INCLUDES = 		-I$(srcdir)/../su

# ----------------------------------------------------------------------
# Build targets

noinst_LTLIBRARIES = 	libbnf.la

check_PROGRAMS = 	torture_bnf

# ----------------------------------------------------------------------
# Rules for building the targets

nobase_include_sofia_HEADERS = sofia-sip/bnf.h

libbnf_la_SOURCES = 	bnf.c

COVERAGE_INPUT = 	$(libbnf_la_SOURCES) $(include_sofia_HEADERS)

LDADD =			libbnf.la

torture_bnf_LDFLAGS = 	-static

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST =		Doxyfile bnf.docs

# ----------------------------------------------------------------------
# Tests

TESTS = torture_bnf

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am
