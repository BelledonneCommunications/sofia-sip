#
# Makefile.am for soa module
#

# ----------------------------------------------------------------------
# Header paths

INCLUDES = 		-I$(srcdir)/../sdp \
			-I$(srcdir)/../sip \
			-I$(srcdir)/../ipt \
			-I$(srcdir)/../su

# ----------------------------------------------------------------------
# Build targets

noinst_LTLIBRARIES = 	libsoa.la

noinst_PROGRAMS =	test_soa

TESTS = 		test_soa

# ----------------------------------------------------------------------
# Rules for building the targets

BUILT_SOURCES =		soa_tag_ref.c

include_HEADERS =       soa.h soa_session.h soa_add.h soa_tag.h

libsoa_la_SOURCES = 	soa.c soa_static.c \
			soa_tag.c soa_tag_ref.c 

COVERAGE_INPUT = 	$(libsoa_la_SOURCES) $(include_HEADERS)

LDADD = 		libsoa.la \
			../sip/libsip.la \
			../sdp/libsdp.la \
			../ipt/libipt.la \
			../su/libsu.la

test_soa_LDFLAGS = 	-static

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST =		Doxyfile soa.docs $(BUILT_SOURCES)

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am

TAG_DLL_FLAGS =		LIST=soa_tag_list
