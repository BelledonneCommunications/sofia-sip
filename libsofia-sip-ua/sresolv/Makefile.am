#
# Makefile.am for sresolv module
#

# ----------------------------------------------------------------------
# Header paths

INCLUDES = 		-I$(srcdir)/../su -I../su

# ----------------------------------------------------------------------
# Build targets

noinst_LTLIBRARIES = 	libsresolv.la

noinst_PROGRAMS = 	test_virgin test_sresolv

TESTS = 		run_test_sresolv

TESTS_ENVIRONMENT =	$(SHELL)

CLEANFILES =		resolv.conf error.conf named.conf.tmp \
			.test_sresolv.api.conf.?????? \
			named.run

# ----------------------------------------------------------------------
# Rules for building the targets

nobase_include_sofia_HEADERS = sofia-sip/sresolv.h

libsresolv_la_SOURCES =	sres.c sres_cache.c sres_blocking.c sresolv.c

COVERAGE_INPUT = 	$(libsresolv_la_SOURCES) $(include_sofia_HEADERS)

LDADD = 		libsresolv.la \
			../su/libsu.la

test_sresolv_LDFLAGS = 	-static
test_virgin_LDFLAGS =   -static

# ----------------------------------------------------------------------
# Distribution

EXTRA_DIST =		Doxyfile sresolv.docs

dist_noinst_DATA = run_test_sresolv \
	127.zone 194.2.188 3.f.f.e.1.2.0.0.3.0.1.2.c.0.0.0 example.com

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am
