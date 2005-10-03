#
# Makefile.am for sdp module
#

DIST_SUBDIRS = 		tests

# ----------------------------------------------------------------------
# Header paths

INCLUDES = 		-I$(srcdir)/../su

# ----------------------------------------------------------------------
# Build targets

noinst_LIBRARIES = 	libsdp.a

noinst_PROGRAMS = 	sdp_torture sdp_test sdp_objs.o

dist_noinst_SCRIPTS =	run-tests

TESTS = 		sdp_torture run-tests

BUILT_SOURCES =		sdp_tag_ref.c

# ----------------------------------------------------------------------
# Rules for building the targets

include_HEADERS =       sdp.h sdp_tag.h

libsdp_a_SOURCES = 	sdp.c sdp_parse.c sdp_print.c \
			sdp_tag.c sdp_tag_ref.c

sdp_objs_o_SOURCES =	$(libsdp_a_SOURCES)
sdp_objs_o_LDADD =	

LDADD = 		libsdp.a \
			-L../su -lsu

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST =		Doxyfile sdp.docs $(BUILT_SOURCES)

# ----------------------------------------------------------------------
# Sofia specific rules

include $(srcdir)/../sofia.am
