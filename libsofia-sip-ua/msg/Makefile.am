#
# Makefile.am for msg module
#

# ----------------------------------------------------------------------
# Header paths

INCLUDES = 	-I$(srcdir)/../bnf \
		-I$(srcdir)/../url \
		-I$(srcdir)/../su

# ----------------------------------------------------------------------
# Build targets

noinst_LTLIBRARIES = 	libmsg.la
noinst_LIBRARIES = 	libtest_msg.a
noinst_PROGRAMS = 	msg_name_hash test_msg

# ----------------------------------------------------------------------
# Rules for building the targets

GENERATED_H = msg_protos.h msg_mime_protos.h
PUBLIC_H = msg.h msg_header.h msg_types.h \
	msg_mclass.h msg_mclass_hash.h msg_parser.h \
	msg_addr.h msg_date.h msg_buffer.h \
	msg_tag_class.h msg_dll.h msg_mime.h
INTERNAL_H = msg_internal.h test_class.h

include_sofia_HEADERS = $(GENERATED_H) $(PUBLIC_H) 

BUILT_SOURCES = $(GENERATED_H) test_table.c test_protos.h

libmsg_la_SOURCES = $(INTERNAL_H) \
	msg.c msg_tag.c \
	msg_mime.c msg_mime_table.c \
	msg_header_copy.c msg_header_make.c \
	msg_parser.c msg_mclass.c msg_parser_util.c \
	msg_basic.c msg_generic.c msg_date.c msg_auth.c

COVERAGE_INPUT = 	$(libmsg_la_SOURCES) $(include_sofia_HEADERS)

libtest_msg_a_SOURCES = test_class.c test_table.c test_protos.h

LDADD = 		libtest_msg.a libmsg.la \
			../bnf/libbnf.la \
			../url/liburl.la \
			../su/libsu.la 

test_msg_LDFLAGS = 	-static

msg_name_hash_LDFLAGS =	-static

# ----------------------------------------------------------------------
# Install and distribution rules

sofialibexecdir =	$(libexecdir)/sofia

dist_sofialibexec_SCRIPTS =	msg_parser.awk

EXTRA_DIST =		Doxyfile msg.docs \
			msg_mime_protos.h.in \
			msg_mime_table.c.in \
			msg_protos.h.in \
			test_protos.h.in \
			test_table.c.in

# ----------------------------------------------------------------------
# Tests

TESTS = 		test_msg

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am

MSG_PARSER_AWK = $(srcdir)/msg_parser.awk

AWK_MSG_AWK = $(AWK) -f $(MSG_PARSER_AWK)

test_protos.h: test_protos.h.in $(MSG_PARSER_AWK)
test_table.c: test_table.c.in $(MSG_PARSER_AWK)

msg_mime_protos.h: msg_mime_protos.h.in $(MSG_PARSER_AWK)
msg_mime_table.c: msg_mime_table.c.in $(MSG_PARSER_AWK)
msg_protos.h: msg_protos.h.in $(MSG_PARSER_AWK)

test_protos.h: test_class.h
	$(AWK_MSG_AWK) module=msg_test NO_MIDDLE=1 NO_LAST=1 \
		PR=$@ TEMPLATE=$(srcdir)/$@.in $<

test_table.c: test_class.h 
	$(AWK_MSG_AWK) module=msg_test prefix=msg \
		MC_HASH_SIZE=127 multipart=msg_multipart \
		PT=$@ $<

msg_protos.h: msg_mime.h
	$(AWK_MSG_AWK) module=msg NO_FIRST=1 NO_MIDDLE=1 \
		PR=$@ TEMPLATE=$(srcdir)/$@.in $<

msg_mime_protos.h: msg_mime.h
	$(AWK_MSG_AWK) module=msg NO_FIRST=1 NO_LAST=1 \
		PR=$@ TEMPLATE=$(srcdir)/$@.in $<

msg_mime_table.c: msg_mime.h
	$(AWK_MSG_AWK) module=msg_multipart \
		tprefix=msg prefix=mp MC_HASH_SIZE=127 \
		PT=$@ $<
