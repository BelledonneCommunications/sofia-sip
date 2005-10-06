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

noinst_LIBRARIES = 	libmsg.a libmsg_test.a
noinst_PROGRAMS = 	msg_name_hash msg_test msg_objs.o

# ----------------------------------------------------------------------
# Rules for building the targets

GENERATED_H = msg_protos.h msg_mime_protos.h
PUBLIC_H = msg.h msg_header.h msg_types.h \
	msg_mclass.h	msg_mclass_hash.h msg_parser.h msg_bnf.h \
	msg_auth.h msg_addr.h msg_date.h msg_buffer.h \
	msg_tag_class.h msg_dll.h msg_mime.h
INTERNAL_H = msg_internal.h msg_test_class.h

include_HEADERS = $(GENERATED_H) $(PUBLIC_H) 

BUILT_SOURCES = $(GENERATED_H) msg_test_table.c msg_test_protos.h

libmsg_a_SOURCES = $(INTERNAL_H) \
	msg.c msg_tag.c \
	msg_mime.c msg_mime_table.c \
	msg_header_copy.c msg_header_make.c \
	msg_parser.c msg_mclass.c msg_parser_util.c \
	msg_basic.c msg_generic.c msg_date.c msg_auth.c \
	memspn.c

msg_objs_o_SOURCES =	$(libmsg_a_SOURCES)
msg_objs_o_LDADD =	

COVERAGE_INPUT = 	$(msg_objs_o_SOURCES) $(include_HEADERS)

libmsg_test_a_SOURCES = msg_test_class.c msg_test_table.c msg_test_protos.h

LDADD = 		libmsg_test.a libmsg.a \
			-L../bnf -lbnf \
			-L../url -lurl \
			-L../su -lsu 

msg_test_SOURCES = 	msg_test.c

msg_name_hash_SOURCES = msg_name_hash.c

# ----------------------------------------------------------------------
# Install and distribution rules

sofialibexecdir =	$(libexecdir)/sofia

dist_sofialibexec_SCRIPTS =	msg_parser.awk

EXTRA_DIST =		Doxyfile msg.docs \
			msg_mime_protos.h.in \
			msg_mime_table.c.in \
			msg_protos.h.in \
			msg_test_protos.h.in \
			msg_test_table.c.in

# ----------------------------------------------------------------------
# Tests

TESTS = 		msg_test

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am

s=$(srcdir)

$s/msg_test_%.h: $s/msg_parser.awk $s/msg_test_%.h.in $s/msg_test_class.h
	$(AWK) -f $s/msg_parser.awk module=msg_test PR=$@ NO_MIDDLE=1 NO_LAST=1 $s/msg_test_class.h

$s/msg_test_table.c: $s/msg_test_class.h $s/msg_test_table.c.in \
	$s/msg_parser.awk 
	$(AWK) -f $s/msg_parser.awk module=msg_test prefix=msg PT=$@ \
		MC_HASH_SIZE=127 multipart=msg_multipart \
		$s/msg_test_class.h

$s/msg_mime_table.c: $s/msg_mime.h $s/msg_mime_table.c.in $s/msg_parser.awk 
	$(AWK) -f $s/msg_parser.awk \
		module=msg_multipart tprefix=msg prefix=mp PT=$@ \
		MC_HASH_SIZE=127 $s/msg_mime.h

$s/msg_protos.h: $s/msg_parser.awk $s/msg_protos.h.in $s/msg_mime.h
	$(AWK) -f $s/msg_parser.awk PR=$@ module=msg NO_FIRST=1 NO_MIDDLE=1 \
		$s/msg_mime.h

$s/msg_mime_protos.h: $s/msg_parser.awk $s/msg_mime_protos.h.in $s/msg_mime.h
	$(AWK) -f $s/msg_parser.awk PR=$@ module=msg NO_FIRST=1 NO_LAST=1 \
		$s/msg_mime.h
