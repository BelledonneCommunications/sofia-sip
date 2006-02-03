#
# Makefile.am for sdp module
#

# ----------------------------------------------------------------------
# Header paths

INCLUDES = 		-I$(srcdir)/../su

# ----------------------------------------------------------------------
# Build targets

noinst_LTLIBRARIES = 	libsdp.la

noinst_PROGRAMS = 	torture_sdp test_sdp

dist_noinst_SCRIPTS =	run_test_sdp

TESTS = 		torture_sdp run_test_sdp

BUILT_SOURCES =		sdp_tag_ref.c

# ----------------------------------------------------------------------
# Rules for building the targets

include_sofia_HEADERS =	sdp.h sdp_tag.h

libsdp_la_SOURCES = 	sdp.c sdp_parse.c sdp_print.c \
			sdp_tag.c sdp_tag_ref.c

COVERAGE_INPUT = 	$(libsdp_la_SOURCES) $(include_sofia_HEADERS)

LDADD = 		libsdp.la \
			../su/libsu.la

sdp_test_LDFLAGS = 	-static
sdp_torture_LDFLAGS = 	-static

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST =		Doxyfile sdp.docs $(BUILT_SOURCES) \
			tests/message-1.sdp \
			tests/message-2.sdp \
			tests/message-3.sdp \
			tests/message-4.sdp \
			tests/message-5.sdp \
			tests/message-6.sdp \
			tests/message-7.sdp \
			tests/message-8.sdp \
			tests/message-9.sdp \
			tests/message-10.sdp

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am
