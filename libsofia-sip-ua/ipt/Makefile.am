#
# Makefile.am for ipt module
#

# ----------------------------------------------------------------------
# Header paths

INCLUDES = 		-I$(srcdir)/../su

# ----------------------------------------------------------------------
# Build targets

noinst_LTLIBRARIES = 	libipt.la

noinst_PROGRAMS = 	sha1test torture_base64

TESTS = 		sha1test torture_base64

# ----------------------------------------------------------------------
# Rules for building the targets

include_HEADERS =       rc4.h utf8.h sha1.h base64.h \
			string0.h token64.h uniqueid.h

libipt_la_SOURCES = 	utf8internal.h \
			utf8.c ucs2.c ucs4.c rc4.c \
			sha1.c base64.c string0.c token64.c

COVERAGE_INPUT = 	$(ipt_objs_o_SOURCES) $(include_HEADERS)

LDADD = 		libipt.la \
			../sresolv/libsresolv.la \
			../su/libsu.la

sha1test_SOURCES = 	sha1test.c

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST =		Doxyfile ipt.docs

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am
