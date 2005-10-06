#
# Makefile.am for bnf module
#

# ----------------------------------------------------------------------
# Header paths

INCLUDES = 		-I$(srcdir)/../su

# ----------------------------------------------------------------------
# Build targets

noinst_LIBRARIES = 	libbnf.a
noinst_PROGRAMS =	bnf_objs.o

check_PROGRAMS = 	torture_bnf

# ----------------------------------------------------------------------
# Rules for building the targets

include_HEADERS =	bnf.h

libbnf_a_SOURCES = 	bnf.c
bnf_objs_o_SOURCES =	$(libbnf_a_SOURCES)
bnf_objs_o_LDADD =	

COVERAGE_INPUT = 	$(bnf_objs_o_SOURCES) $(include_HEADERS)

LDADD =			libbnf.a

torture_bnf_SOURCES = 	torture_bnf.c

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST =		Doxyfile bnf.docs

# ----------------------------------------------------------------------
# Tests

TESTS = torture_bnf

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am
