#
# Makefile.am for sip module
#

# ----------------------------------------------------------------------
# Header paths

INCLUDES = 	-I$(srcdir)/../bnf \
		-I$(srcdir)/../ipt \
		-I$(srcdir)/../msg \
		-I$(srcdir)/../url \
		-I$(srcdir)/../su

# ----------------------------------------------------------------------
# Build targets

noinst_LIBRARIES = 	libsip.a

noinst_PROGRAMS =       torture_sip \
			sip_test_msg validator date_test \
			sip_objs.o

# ----------------------------------------------------------------------
# Rules for building the targets

GENERATED_H = sip_hclasses.h sip_protos.h sip_tag.h sip_rfc2543.h
H_IN = sip_hclasses.h.in sip_protos.h.in sip_tag.h.in

PUBLIC_H = sip.h sip_extensions.h sip_util.h \
           sip_header.h sip_parser.h \
	   sip_tag_class.h sip_dll.h sip_status.h
INTERNAL_H = sip_internal.h 

GENERATED_C = sip_tag.c sip_tag_ref.c sip_parser_table.c

# EXTRA_DIST = $(GENERATED_C:%.in=%)

BUILT_SOURCES = 	$(GENERATED_H) $(GENERATED_C)

include_HEADERS = 	$(GENERATED_H) $(PUBLIC_H) $(H_IN)

libsip_a_SOURCES = 	$(INTERNAL_H) \
			sip_parser.c sip_header.c sip_util.c sip_pref_util.c \
			sip_basic.c sip_extra.c sip_feature.c sip_mime.c \
			sip_security.c sip_event.c sip_prack.c \
			sip_refer.c sip_session.c \
			sip_caller_prefs.c sip_reason.c \
			sip_status.c sip_time.c \
			sip_tag_class.c \
			$(GENERATED_C)

sip_objs_o_SOURCES =	$(libsip_a_SOURCES)
sip_objs_o_LDADD =	

LDADD = 		libsip.a \
			-L../msg -lmsg \
			-L../bnf -lbnf \
			-L../url -lurl \
			-L../su -lsu 

# ----------------------------------------------------------------------
# Install and distribution rules

# note: srcdir needs to be specified, otherwise
#       breaks make distcheck target

EXTRA_DIST =		Doxyfile sip.docs sip_parser.docs \
			ADD-A-HEADER GRAMMAR sip_bad_mask \
			sip_parser_table.c.in sip_tag.c.in \
			sip_rfc2543.h.in sip_rfc2543.c \
			sip_bad_mask

SUBDIRS = 		images tests

# ----------------------------------------------------------------------
# Tests

TESTS = torture_sip run_sip_test_msg run_date_test

dist_noinst_SCRIPTS = 	run_sip_test_msg run_date_test

# ----------------------------------------------------------------------
# Sofia specific rules

include ../sofia.am

s = $(srcdir)
m = $(s)/../msg

SIP_H = $s/sip.h 

#
# Note: sip_bad_mask is used by nta to weed out bad messages
#
$s/sip_parser_table.c: \
		$m/msg_parser.awk $s/sip_parser_table.c.in \
		${SIP_H} $s/sip_bad_mask
	$(AWK) -f $m/msg_parser.awk module=sip PT=$@ \
		FLAGFILE=$s/sip_bad_mask \
		MC_HASH_SIZE=127 MC_SHORT_SIZE=26 ${SIP_H}

$s/sip_%.h: $m/msg_parser.awk $s/sip_%.h.in ${SIP_H}
	$(AWK) -f $m/msg_parser.awk module=sip PR=$@ ${SIP_H}

$s/sip_%.c: $m/msg_parser.awk $s/sip_%.c.in ${SIP_H}
	$(AWK) -f $m/msg_parser.awk module=sip PR=$@ ${SIP_H}
