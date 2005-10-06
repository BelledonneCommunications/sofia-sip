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

noinst_LIBRARIES = 	libsoa.a

noinst_PROGRAMS =	soa_objs.o test_soa

TESTS = 		test_soa

# ----------------------------------------------------------------------
# Rules for building the targets

BUILT_SOURCES =		soa_tag_ref.c

include_HEADERS =       soa.h soa_session.h soa_add.h soa_tag.h

libsoa_a_SOURCES = 	soa.c soa_static.c \
			soa_tag.c soa_tag_ref.c 

soa_objs_o_SOURCES =	$(libsoa_a_SOURCES)
soa_objs_o_LDADD =

COVERAGE_INPUT = 	$(soa_objs_o_SOURCES) $(include_HEADERS)

LDADD = 		libsoa.a \
			-L../sip -lsip \
			-L../sdp -lsdp \
			-L../ipt -lipt \
			-L../su -lsu

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST =		Doxyfile soa.docs $(BUILT_SOURCES)

# ----------------------------------------------------------------------
# Sofia specific rules

include $(srcdir)/../sofia.am

TAG_DLL_FLAGS =		LIST=soa_tag_list
