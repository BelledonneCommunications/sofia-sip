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

noinst_PROGRAMS = 	test_http

TESTS = 		test_http

# ----------------------------------------------------------------------
# Rules for building the targets

PUBLIC_H = 		sofia-sip/http.h sofia-sip/http_header.h \
			sofia-sip/http_parser.h sofia-sip/http_tag_class.h \
			sofia-sip/http_status.h sofia-sip/http_hclasses.h

BUILT_H = 		sofia-sip/http_protos.h sofia-sip/http_tag.h 
BUILT_C = 		http_tag.c http_tag_ref.c http_parser_table.c

BUILT_SOURCES = 	$(BUILT_H) $(BUILT_C)

nobase_include_sofia_HEADERS = $(BUILT_H) $(PUBLIC_H) 

libhttp_la_SOURCES = 	$(INTERNAL_H) \
			http_parser.c http_header.c \
			http_basic.c http_extra.c \
			http_status.c http_tag_class.c \
			$(BUILT_C)

COVERAGE_INPUT = 	$(libhttp_la_SOURCES) $(include_sofia_HEADERS)

LDADD = 		libhttp.la \
			../bnf/libbnf.la \
			../msg/libmsg.la \
			../url/liburl.la \
			../su/libsu.la

test_http_LDFLAGS = 	-static

# ----------------------------------------------------------------------
# Install and distribution rules

EXTRA_DIST =		Doxyfile http.docs \
			sofia-sip/http_parser_table.c.in \
			sofia-sip/http_protos.h.in \
			sofia-sip/http_tag.h.in \
			http_tag.c.in

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am

TAG_DLL_FLAGS = DLLREF=1

MSG_PARSER_AWK = $(srcdir)/../msg/msg_parser.awk

AWK_HTTP_AWK = $(AWK) -f $(MSG_PARSER_AWK) module=http

sofia-sip/http_tag.h: sofia-sip/http_tag.h.in $(MSG_PARSER_AWK)
sofia-sip/http_protos.h: sofia-sip/http_protos.h.in $(MSG_PARSER_AWK)
http_tag.c: http_tag.c.in $(MSG_PARSER_AWK)
http_parser_table.c: http_parser_table.c.in $(MSG_PARSER_AWK)

sofia-sip/http_tag.c sofia-sip/http_protos.h sofia-sip/http_tag.h: \
	sofia-sip/http.h
	$(AWK_HTTP_AWK) PR=$@ TEMPLATE=$(srcdir)/$@.in $<

http_parser_table.c: sofia-sip/http.h
	$(AWK_HTTP_AWK) PT=$@ MC_HASH_SIZE=127 $<
