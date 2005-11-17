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

noinst_LTLIBRARIES = 	libsip.la

noinst_PROGRAMS =       torture_sip \
			sip_test_msg validator date_test

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

include_sofia_HEADERS = 	$(GENERATED_H) $(PUBLIC_H) $(H_IN)

libsip_la_SOURCES = 	$(INTERNAL_H) \
			sip_parser.c sip_header.c sip_util.c sip_pref_util.c \
			sip_basic.c sip_extra.c sip_feature.c sip_mime.c \
			sip_security.c sip_event.c sip_prack.c \
			sip_refer.c sip_session.c \
			sip_caller_prefs.c sip_reason.c \
			sip_status.c sip_time.c \
			sip_tag_class.c \
			$(GENERATED_C)

COVERAGE_INPUT = 	$(libsip_la_SOURCES) $(include_sofia_HEADERS)

LDADD = 		libsip.la \
			../msg/libmsg.la \
			../bnf/libbnf.la \
			../url/liburl.la \
			../su/libsu.la

torture_sip_LDFLAGS = 	-static
sip_test_msg_LDFLAGS = 	-static
date_test_LDFLAGS = 	-static

# ----------------------------------------------------------------------
# Install and distribution rules

# note: srcdir needs to be specified, otherwise
#       breaks make distcheck target

EXTRA_DIST =		Doxyfile sip.docs sip_parser.docs \
			ADD-A-HEADER GRAMMAR sip_bad_mask \
			sip_parser_table.c.in sip_tag.c.in \
			sip_rfc2543.h.in sip_rfc2543.c \
			sip_bad_mask \
	images/sip-parser.eps images/sip-parser.gif \
	images/sip-parser2.eps images/sip-parser2.gif \
	images/sip-parser3.eps images/sip-parser3.gif \
	images/sip-parser4.eps images/sip-parser4.gif \
	tests/own0.txt tests/own1.txt tests/own2.txt tests/own3.txt \
	tests/own4.txt tests/own5.txt tests/own6.txt \
	tests/test1.txt tests/test-ack-1.txt tests/test2.txt tests/test3.txt \
	tests/test4.txt tests/test5.txt tests/test6.txt tests/test7.txt	     \
	tests/test8.txt tests/test9.txt tests/test10.txt tests/test10b.txt   \
	tests/test10c.txt tests/test11.txt tests/test12.txt tests/test13.txt \
	tests/test14-req.txt tests/test14.txt tests/test15.txt		     \
	tests/test16.txt tests/test17.txt tests/test18.txt tests/test19.txt  \
	tests/test1a.txt tests/test20.txt tests/test21.txt tests/test22.txt  \
	tests/test23.txt tests/test24.txt tests/test25.txt tests/test26.txt  \
	tests/test27.txt tests/test28.txt tests/test29.txt tests/test30.txt  \
	tests/test31.txt tests/test32.txt tests/test33.txt tests/test34.txt  \
	tests/test35.txt tests/test36.txt tests/test37.txt tests/test38.txt  \
	tests/test39.txt tests/test40.txt tests/test41.txt tests/test42.txt

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
