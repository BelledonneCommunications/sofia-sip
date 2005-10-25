#
# Makefile.am for http module
#

# ----------------------------------------------------------------------
# Header paths

INCLUDES = 	-I$(srcdir)/../bnf \
		-I$(srcdir)/../msg \
		-I$(srcdir)/../url \
		-I$(srcdir)/../su 

# ----------------------------------------------------------------------
# Build targets

noinst_LTLIBRARIES = 	libhttp.la

noinst_PROGRAMS = 	http_test

TESTS = 		http_test

# ----------------------------------------------------------------------
# Rules for building the targets

PUBLIC_H = http.h http_header.h http_parser.h \
	   http_tag_class.h http_dll.h http_status.h http_hclasses.h

BUILT_H = http_protos.h http_tag.h 
BUILT_C = http_tag.c http_tag_ref.c http_parser_table.c

BUILT_SOURCES = $(BUILT_H) $(BUILT_C)

include_HEADERS = 	$(BUILT_H) $(PUBLIC_H) 

libhttp_la_SOURCES = 	$(INTERNAL_H) \
			http_parser.c http_header.c \
			http_basic.c http_extra.c \
			http_status.c http_tag_class.c \
			$(BUILT_C)

COVERAGE_INPUT = 	$(libhttp_la_SOURCES) $(include_HEADERS)

LDADD = 		libhttp.la \
			../bnf/libbnf.la \
			../msg/libmsg.la \
			../url/liburl.la \
			../su/libsu.la

http_test_LDFLAGS = 	-static

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST =		Doxyfile http.docs \
			http_parser_table.c.in \
			http_protos.h.in \
			http_tag.c.in \
			http_tag.h.in 

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am

TAG_DLL_FLAGS =		DLLREF=1

s = $(srcdir)
m = $(top_srcdir)/libsofia-sip-ua/msg

$s/http_parser_table.c: $m/msg_parser.awk $s/http.h $s/http_parser_table.c.in
	$(AWK) -f $m/msg_parser.awk module=http PT=$@ \
		MC_HASH_SIZE=127 $s/http.h

$s/http_%.h: $m/msg_parser.awk $s/http_%.h.in $s/http.h
	$(AWK) -f $m/msg_parser.awk module=http PR=$@ $s/http.h

$s/http_%.c: $m/msg_parser.awk $s/http_%.c.in $s/http.h
	$(AWK) -f $m/msg_parser.awk module=http PR=$@ $s/http.h

