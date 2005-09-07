#
# Makefile.am for url module
#

# ----------------------------------------------------------------------
# Header paths

INCLUDES = 	-I$(srcdir)/../bnf \
		-I$(srcdir)/../su

# ----------------------------------------------------------------------
# Build targets

noinst_LIBRARIES = 	liburl.a

noinst_PROGRAMS = 	torture_url test_urlmap url_objs.o

# ----------------------------------------------------------------------
# Rules for building the targets

BUILT_SOURCES =		url_tag_ref.c

include_HEADERS =       url.h url_dll.h url_tag.h url_tag_class.h

liburl_a_SOURCES = 	url.c url_tag.c url_tag_ref.c

url_objs_o_SOURCES =	$(liburl_a_SOURCES)
url_objs_o_LDADD =	

LDADD = 		liburl.a \
			-L../bnf -lbnf \
			-L../su -lsu 

test_urlmap_SOURCES = 	urlmap.c urlmap.h
test_urlmap_CFLAGS =	$(CFLAGS) -DTEST_URLMAP=1

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST =		Doxyfile url.docs $(BUILT_SOURCES)

# ----------------------------------------------------------------------
# Tests

TESTS = 		torture_url test_urlmap

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am

TAG_DLL_FLAGS = 	DLLREF=1
