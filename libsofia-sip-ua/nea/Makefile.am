#
# Makefile.am for nea module
#

# ----------------------------------------------------------------------
# Header paths

INCLUDES = 	-I$(srcdir)/../ipt \
		-I$(srcdir)/../msg \
		-I$(srcdir)/../nta \
		-I$(srcdir)/../sip \
		-I$(srcdir)/../sresolv \
		-I$(srcdir)/../tport \
		-I$(srcdir)/../url \
		-I$(srcdir)/../su

# ----------------------------------------------------------------------
# Build targets

noinst_LTLIBRARIES = 	libnea.la

TESTS = 

# ----------------------------------------------------------------------
# Rules for building the targets

BUILT_SOURCES =		nea_tag_ref.c

include_sofia_HEADERS =       nea.h nea_debug.h

libnea_la_SOURCES = 	nea.c nea_event.c \
			nea_server.c nea_debug.c nea_tag.c nea_tag_ref.c

COVERAGE_INPUT = 	$(libnea_la_SOURCES) $(include_sofia_HEADERS)

LDADD = 		libnea.la \
			../nta/libnta.la \
			../ipt/libipt.la \
			../sip/libsip.la \
			../sresolv/libsresolv.la \
			../tport/libtport.la \
			../stun/libstun.la \
			../url/liburl.la \
			../msg/libmsg.la \
			../bnf/libbnf.la \
			../su/libsu.la 

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST =		Doxyfile nea.docs $(BUILT_SOURCES)

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am
