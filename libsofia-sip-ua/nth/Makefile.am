#
# Makefile.am for nth module
#

# ----------------------------------------------------------------------
# Header paths

INCLUDES = 	-I$(srcdir)/../ipt \
		-I$(srcdir)/../iptsec \
		-I$(srcdir)/../msg \
		-I$(srcdir)/../http \
		-I$(srcdir)/../sresolv \
		-I$(srcdir)/../tport \
		-I$(srcdir)/../url \
		-I$(srcdir)/../su

# ----------------------------------------------------------------------
# Build targets

noinst_LTLIBRARIES = 	libnth.la

# noinst_PROGRAMS = 	nth_test http-client http-server

# TESTS = 		nth_test
TESTS = 

# ----------------------------------------------------------------------
# Rules for building the targets

BUILT_SOURCES =		nth_tag_ref.c

include_sofia_HEADERS =       nth.h nth_tag.h

libnth_la_SOURCES = 	nth_client.c nth_server.c nth_tag.c nth_tag_ref.c

COVERAGE_INPUT = 	$(libnth_la_SOURCES) $(include_sofia_HEADERS)

LDADD = 		libnth.la \
			../iptsec/libiptsec.la \
			../ipt/libipt.la \
			../http/libhttp.la \
			../sresolv/libsresolv.la \
			../tport/libtport.la \
			../stun/libstun.la \
			../url/liburl.la \
			../msg/libmsg.la \
			../bnf/libbnf.la \
			../su/libsu.la

nth_test_LDFLAGS = 	-static

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST =		Doxyfile nth.docs $(BUILT_SOURCES) \
			agent.pem cafile.pem

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am
